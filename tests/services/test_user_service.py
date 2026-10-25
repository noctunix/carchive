"""Tests for `carchive.services.user_service`.

No real `systemctl`, `loginctl` or `journalctl` ever runs: every test injects `FakeSystemd`,
and an autouse guard makes the default runner fail loudly.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from carchive.services import user_service
from carchive.services.user_service import (
    Host,
    UnsupportedEnvironmentError,
    UserServiceError,
)

_REAL_RUN_COMMAND = user_service.run_command

USER = "alice"
HOST = Host(uid=1000, user=USER, systemctl="/usr/bin/systemctl")


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")

    def _forbidden(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"a real command would have run: {list(argv)}")

    monkeypatch.setattr(user_service, "run_command", _forbidden)
    return config / "systemd" / "user" / "carchive.service"


@pytest.fixture
def unit_file(_isolated_home: Path) -> Path:
    return _isolated_home


class FakeSystemd:
    """Stands in for `systemctl`, `loginctl` and `journalctl`, recording every call."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.active = "inactive"
        self.enabled = "disabled"
        self.user_manager_ok = True
        self.linger = False
        self.linger_query_rc = 0
        self.enable_linger_rc = 0
        self.journal = "line one\nline two\n"
        self.journal_rc = 0
        self.failing: dict[str, int] = {}
        self.timing_out: set[str] = set()

    def __call__(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        self.calls.append(args)
        key = " ".join(args[2:] if args[:2] == ["systemctl", "--user"] else args[:2])
        if key in self.timing_out:
            raise subprocess.TimeoutExpired(args, 60)
        if key in self.failing:
            return _done(args, self.failing[key], stderr="Failed to connect to bus\nmore\n")
        if args[0] == "systemctl":
            return self._systemctl(args)
        if args[0] == "loginctl":
            return self._loginctl(args)
        if args[0] == "journalctl":
            return _done(args, self.journal_rc, stdout=self.journal)
        raise AssertionError(f"unexpected command {args}")

    def _systemctl(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        sub = args[2]
        if sub == "show-environment":
            return _done(args, 0 if self.user_manager_ok else 1)
        if sub == "is-active":
            return _done(args, 0 if self.active == "active" else 3, stdout=self.active + "\n")
        if sub == "is-enabled":
            return _done(args, 0 if self.enabled == "enabled" else 1, stdout=self.enabled + "\n")
        if sub in ("enable", "restart", "disable", "daemon-reload"):
            if sub == "enable" and "--now" in args:
                self.active = "active"
            if sub == "enable":
                self.enabled = "enabled"
            return _done(args, 0)
        raise AssertionError(f"unexpected systemctl call {args}")

    def _loginctl(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[1] == "show-user":
            return _done(
                args, self.linger_query_rc, stdout=f"Linger={'yes' if self.linger else 'no'}\n"
            )
        if args[1] == "enable-linger":
            if self.enable_linger_rc == 0:
                self.linger = True
            return _done(
                args, self.enable_linger_rc, stderr="Interactive authentication required\n"
            )
        raise AssertionError(f"unexpected loginctl call {args}")

    def subcommands(self) -> list[str]:
        """Return the systemctl sub-commands (with arguments) in call order."""
        return [" ".join(c[2:]) for c in self.calls if c[:2] == ["systemctl", "--user"]]

    def ran(self, program: str) -> list[list[str]]:
        """Return the calls made to one program."""
        return [c for c in self.calls if c[0] == program]


def _done(
    args: Sequence[str], returncode: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(list(args), returncode, stdout, stderr)


class Lines:
    """Collects output lines."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


COMMAND = ["/opt/carchive/bin/carchive"]


def _install(
    fake: FakeSystemd,
    *,
    start: bool = True,
    host: Host = HOST,
    command: Sequence[str] = COMMAND,
) -> tuple[Lines, Lines]:
    out, err = Lines(), Lines()
    user_service.install(start=start, out=out, err=err, runner=fake, host=host, command=command)
    return out, err


# --- quoting -------------------------------------------------------------------------------


def _split_exec_start(text: str) -> list[str]:
    """Minimal inverse of systemd's ExecStart= word splitting, for round-trip checks."""
    words: list[str] = []
    current = ""
    in_word = False
    quoted = False
    i = 0
    while i < len(text):
        char = text[i]
        if quoted and char == "\\":
            current += text[i + 1]
            i += 2
            continue
        if char == '"':
            quoted = not quoted
            in_word = True
        elif char == " " and not quoted:
            if in_word:
                words.append(current)
            current, in_word = "", False
        elif char in "%$" and text[i + 1 : i + 2] == char:
            current += char
            in_word = True
            i += 1
        else:
            current += char
            in_word = True
        i += 1
    if in_word:
        words.append(current)
    return words


@pytest.mark.parametrize(
    "path",
    [
        "/home/alice/.local/bin/carchive",
        "/home/alice/my tools/carchive",
        '/home/alice/we"ird/carchive',
        "/home/alice/back\\slash/carchive",
        "/home/alice/100%/carchive",
        "/home/alice/$HOME/carchive",
        "/home/alice/it's/carchive",
        "/home/alice/semi;colon/carchive",
        "/home/alice/ünï/carchive",
    ],
)
def test_exec_start_round_trips_special_characters(path: str) -> None:
    line = user_service.exec_start_line([path])
    assert "\n" not in line
    assert _split_exec_start(line) == [path, "serve"]


def test_plain_path_is_not_quoted() -> None:
    assert user_service.exec_start_line(["/home/a/.local/bin/carchive"]) == (
        "/home/a/.local/bin/carchive serve"
    )


def test_percent_and_dollar_are_doubled() -> None:
    assert user_service.systemd_quote("/a/100%/b") == "/a/100%%/b"
    assert user_service.systemd_quote("/a/$x/b") == "/a/$$x/b"
    assert user_service.systemd_quote("/a b/%h") == '"/a b/%%h"'


@pytest.mark.parametrize(
    "bad", ["", "/a/b\nExecStartPre=/bin/evil", "/a/b\r", "/a/\x00b", "/a/\x7fb"]
)
def test_control_characters_are_rejected(bad: str) -> None:
    with pytest.raises(UserServiceError):
        user_service.systemd_quote(bad)


def test_relative_program_path_is_rejected() -> None:
    with pytest.raises(UserServiceError, match="absolute"):
        user_service.exec_start_line(["carchive"])


def test_unit_with_quote_in_path_keeps_a_single_exec_start_line() -> None:
    line = user_service.exec_start_line(['/a/b" ExecStartPre=/bin/evil'])
    text = user_service.render_unit(line)
    assert [ln for ln in text.splitlines() if ln.startswith("Exec")] == [f"ExecStart={line}"]


# --- resolving the program ---------------------------------------------------------------


def _make_program(path: Path, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(mode)
    return path


def test_resolve_uses_running_carchive_program(tmp_path: Path) -> None:
    program = _make_program(tmp_path / "bin" / "carchive")
    assert user_service.resolve_exec_command(str(program), "/usr/bin/python3") == [str(program)]


def test_resolve_keeps_symlink_path(tmp_path: Path) -> None:
    target = _make_program(tmp_path / "venv" / "bin" / "carchive")
    link = tmp_path / "bin" / "carchive"
    link.parent.mkdir()
    link.symlink_to(target)
    assert user_service.resolve_exec_command(str(link), "/usr/bin/python3") == [str(link)]


def test_resolve_makes_relative_argv0_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    program = _make_program(tmp_path / "bin" / "carchive")
    monkeypatch.chdir(tmp_path)
    assert user_service.resolve_exec_command("./bin/carchive", "/usr/bin/python3") == [str(program)]


def test_resolve_looks_up_bare_name_on_path(tmp_path: Path) -> None:
    program = _make_program(tmp_path / "bin" / "carchive")
    result = user_service.resolve_exec_command(
        "carchive",
        "/usr/bin/python3",
        which=lambda name: str(program) if name == "carchive" else None,
    )
    assert result == [str(program)]


@pytest.mark.parametrize("argv0", ["/nonexistent/carchive", ""])
def test_resolve_falls_back_to_module_when_program_missing(argv0: str) -> None:
    assert user_service.resolve_exec_command(argv0, "/usr/bin/python3", which=lambda _: None) == [
        "/usr/bin/python3",
        "-m",
        "carchive",
    ]


def test_resolve_falls_back_for_other_program_name(tmp_path: Path) -> None:
    other = _make_program(tmp_path / "bin" / "pytest")
    assert user_service.resolve_exec_command(str(other), "/usr/bin/python3") == [
        "/usr/bin/python3",
        "-m",
        "carchive",
    ]


def test_resolve_falls_back_for_non_executable_program(tmp_path: Path) -> None:
    program = _make_program(tmp_path / "bin" / "carchive", mode=0o644)
    assert user_service.resolve_exec_command(str(program), "/usr/bin/python3")[1:] == [
        "-m",
        "carchive",
    ]


def test_resolve_rejects_relative_interpreter() -> None:
    with pytest.raises(UserServiceError, match="absolute"):
        user_service.resolve_exec_command("/nonexistent/x", "python3")


# --- paths and unit text -------------------------------------------------------------------


def test_unit_path_uses_xdg_config_home(unit_file: Path) -> None:
    assert user_service.unit_path() == unit_file


def test_unit_path_falls_back_to_home_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME")
    expected = tmp_path / "home" / ".config" / "systemd" / "user" / "carchive.service"
    assert user_service.unit_path() == expected


def test_unit_path_ignores_relative_xdg_config_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/dir")
    assert user_service.unit_path().is_relative_to(tmp_path / "home")


def test_rendered_unit_content() -> None:
    text = user_service.render_unit("/x/carchive serve")
    lines = text.splitlines()
    assert "ExecStart=/x/carchive serve" in lines
    for expected in (
        "Restart=on-failure",
        "RestartSec=30",
        "TimeoutStopSec=30",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "LockPersonality=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "WantedBy=default.target",
    ):
        assert expected in lines
    assert not any(line.startswith("Environment") for line in lines)


# --- install -------------------------------------------------------------------------------


def test_install_writes_unit_registers_and_enables_linger(unit_file: Path) -> None:
    fake = FakeSystemd()

    out, err = _install(fake)

    assert unit_file.read_text() == user_service.render_unit("/opt/carchive/bin/carchive serve")
    assert stat.S_IMODE(unit_file.stat().st_mode) == 0o600
    assert fake.subcommands() == [
        "show-environment",
        "is-active carchive.service",
        "daemon-reload",
        "enable --now carchive.service",
    ]
    assert fake.linger is True
    assert err.lines == []
    assert any("wrote" in line for line in out.lines)
    assert "enabled lingering" in out.lines
    assert not list(unit_file.parent.glob(".carchive.service.*")), "temporary file left behind"


def test_install_no_start_only_enables(unit_file: Path) -> None:
    fake = FakeSystemd()

    _install(fake, start=False)

    assert "enable carchive.service" in fake.subcommands()
    assert not any("--now" in sub for sub in fake.subcommands())
    assert fake.active == "inactive"


def test_install_is_idempotent_for_identical_unit(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)
    inode = unit_file.stat().st_ino
    fake.calls.clear()

    out, err = _install(fake)

    assert unit_file.stat().st_ino == inode, "identical unit must not be rewritten"
    assert "unit unchanged" in out.text
    assert not any("restart" in sub for sub in fake.subcommands())
    assert fake.ran("loginctl") == [["loginctl", "show-user", USER, "-p", "Linger"]]
    assert "lingering already enabled" in out.lines
    assert err.lines == []


def test_install_changed_unit_is_rewritten_and_running_service_restarted(
    unit_file: Path,
) -> None:
    fake = FakeSystemd()
    _install(fake)
    fake.calls.clear()

    out, _ = _install(fake, command=["/other/place/carchive"])

    assert "/other/place/carchive serve" in unit_file.read_text()
    assert "updated" in out.text
    subs = fake.subcommands()
    assert subs.index("daemon-reload") < subs.index("restart carchive.service")


def test_install_changed_unit_without_running_service_does_not_restart(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake, start=False)
    fake.calls.clear()

    _install(fake, start=False, command=["/other/carchive"])

    assert not any(sub.startswith("restart") for sub in fake.subcommands())


def test_install_no_start_with_running_changed_unit_prints_restart_hint(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)
    fake.calls.clear()

    out, _ = _install(fake, start=False, command=["/other/carchive"])

    assert not any(sub.startswith("restart") for sub in fake.subcommands())
    assert "systemctl --user restart carchive.service" in out.text


@pytest.mark.parametrize(
    ("host", "fake_setup", "message"),
    [
        (Host(1000, USER, None), lambda f: None, "systemctl not found"),
        (Host(0, "root", "/usr/bin/systemctl"), lambda f: None, "root"),
        (HOST, lambda f: setattr(f, "user_manager_ok", False), "user manager"),
    ],
    ids=["no-systemctl", "root", "no-user-manager"],
)
def test_install_fails_closed_without_usable_environment(
    unit_file: Path, host: Host, fake_setup: Any, message: str
) -> None:
    fake = FakeSystemd()
    fake_setup(fake)

    with pytest.raises(UnsupportedEnvironmentError, match=message):
        _install(fake, host=host)

    assert not unit_file.exists()
    assert not unit_file.parent.exists()
    assert fake.subcommands() in ([], ["show-environment"])
    assert fake.ran("loginctl") == []


def test_unsupported_environment_messages_point_to_the_readme() -> None:
    fake = FakeSystemd()
    with pytest.raises(UnsupportedEnvironmentError, match="Running Carchive"):
        _install(fake, host=Host(1000, USER, None))
    fake.user_manager_ok = False
    with pytest.raises(UnsupportedEnvironmentError, match="Running Carchive"):
        _install(fake)


def test_install_daemon_reload_failure_reports_exit_code_without_traceback(
    unit_file: Path,
) -> None:
    fake = FakeSystemd()
    fake.failing["daemon-reload"] = 1

    with pytest.raises(UserServiceError, match=r"daemon-reload` failed \(exit 1\)") as info:
        _install(fake)

    assert "Failed to connect to bus" in str(info.value)
    assert "more" not in str(info.value), "only the first stderr line is reported"
    assert fake.ran("loginctl") == []
    assert not any(sub.startswith("enable") for sub in fake.subcommands())


def test_install_enable_failure_is_reported() -> None:
    fake = FakeSystemd()
    fake.failing["enable --now carchive.service"] = 1
    with pytest.raises(UserServiceError, match="enable --now"):
        _install(fake)


@pytest.mark.parametrize("key", ["daemon-reload", "is-active carchive.service"])
def test_install_subprocess_timeout_is_a_clean_error(key: str) -> None:
    fake = FakeSystemd()
    fake.timing_out.add(key)
    with pytest.raises(UserServiceError, match="timed out"):
        _install(fake)


def test_install_program_that_cannot_start_is_a_clean_error() -> None:
    def broken(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["systemctl", "--user", "show-environment"]:
            return _done(argv, 0)
        raise PermissionError(13, "Permission denied")

    with pytest.raises(UserServiceError, match="Permission denied"):
        user_service.install(out=Lines(), err=Lines(), runner=broken, host=HOST, command=COMMAND)


def test_install_linger_enable_failure_warns_but_succeeds(unit_file: Path) -> None:
    fake = FakeSystemd()
    fake.enable_linger_rc = 1

    out, err = _install(fake)

    assert unit_file.exists()
    assert "sudo loginctl enable-linger alice" in err.text
    assert "warning" in err.text
    assert fake.linger is False


def test_install_unknown_linger_state_still_attempts_enable() -> None:
    fake = FakeSystemd()
    fake.linger_query_rc = 1

    out, err = _install(fake)

    assert ["loginctl", "enable-linger", USER] in fake.calls
    assert err.lines == []
    assert "enabled lingering" in out.lines


def test_install_linger_command_timeout_only_warns() -> None:
    fake = FakeSystemd()
    fake.timing_out.add("loginctl enable-linger")

    _, err = _install(fake)

    assert "sudo loginctl enable-linger alice" in err.text


def test_install_refuses_to_replace_a_symlink(unit_file: Path, tmp_path: Path) -> None:
    unit_file.parent.mkdir(parents=True)
    target = tmp_path / "dotfiles-unit"
    target.write_text("keep me")
    unit_file.symlink_to(target)

    with pytest.raises(UserServiceError, match="symlink"):
        _install(FakeSystemd())

    assert target.read_text() == "keep me"


def test_install_unwritable_location_is_a_clean_error(unit_file: Path) -> None:
    unit_file.parent.parent.mkdir(parents=True)
    unit_file.parent.write_text("not a directory")

    with pytest.raises(UserServiceError, match="cannot write"):
        _install(FakeSystemd())


def test_install_failed_write_leaves_no_temporary_file(
    unit_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_replace(src: Any, dst: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(UserServiceError, match="No space left"):
        _install(FakeSystemd())

    assert not unit_file.exists()
    assert list(unit_file.parent.iterdir()) == []


def test_install_overwrite_is_atomic_keeps_old_unit_on_failure(
    unit_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(FakeSystemd())
    original = unit_file.read_text()
    monkeypatch.setattr(os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError(5, "io")))

    with pytest.raises(UserServiceError):
        _install(FakeSystemd(), command=["/other/carchive"])

    assert unit_file.read_text() == original


# --- uninstall -----------------------------------------------------------------------------


def test_uninstall_removes_unit_and_keeps_linger(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)
    fake.calls.clear()
    out = Lines()

    user_service.uninstall(out=out, runner=fake, host=HOST)

    assert not unit_file.exists()
    assert fake.subcommands() == [
        "show-environment",
        "disable --now carchive.service",
        "daemon-reload",
    ]
    assert fake.ran("loginctl") == []
    assert "lingering left unchanged" in out.text


def test_uninstall_without_unit_is_not_an_error(unit_file: Path) -> None:
    fake = FakeSystemd()
    out = Lines()

    user_service.uninstall(out=out, runner=fake, host=HOST)

    assert "not installed" in out.text
    assert fake.subcommands() == ["show-environment"]


def test_uninstall_twice_is_fine(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)

    user_service.uninstall(out=Lines(), runner=fake, host=HOST)
    user_service.uninstall(out=Lines(), runner=fake, host=HOST)


def test_uninstall_disable_failure_keeps_the_unit(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)
    fake.failing["disable --now carchive.service"] = 1

    with pytest.raises(UserServiceError, match="disable --now"):
        user_service.uninstall(out=Lines(), runner=fake, host=HOST)

    assert unit_file.exists()


def test_uninstall_fails_closed_as_root(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)

    with pytest.raises(UnsupportedEnvironmentError):
        user_service.uninstall(out=Lines(), runner=fake, host=Host(0, "root", "/usr/bin/systemctl"))

    assert unit_file.exists()


# --- status --------------------------------------------------------------------------------


def _status(fake: FakeSystemd, url: str | None = None) -> user_service.ServiceStatus:
    return user_service.status(url=url, runner=fake, host=HOST)


def test_status_healthy(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)

    report = _status(fake, url="http://127.0.0.1:8470")

    assert report.problems == []
    assert report.installed and report.enabled == "enabled" and report.active == "active"
    assert report.linger is True
    assert "url: http://127.0.0.1:8470" in report.render()
    assert fake.ran("journalctl") == [
        ["journalctl", "--user", "-u", "carchive.service", "-n", "15", "--no-pager"]
    ]


def test_status_prints_journal_lines_unmodified_and_adds_nothing(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)
    journal = ['Oct 23 12:00:00 host carchive[1]: {"event": "x"}', "  indented  ", "", "%s $HOME"]
    fake.journal = "\n".join(journal) + "\n"

    rendered = _status(fake).render()

    assert rendered[-len(journal) :] == journal
    assert rendered[: -len(journal)] == [
        f"unit: installed ({unit_file})",
        "enabled: enabled",
        "active: active",
        "linger: on",
        "journal (last 15 lines):",
    ]


def test_status_keeps_at_most_fifteen_journal_lines(unit_file: Path) -> None:
    fake = FakeSystemd()
    fake.journal = "".join(f"l{i}\n" for i in range(40))

    assert _status(fake).journal == tuple(f"l{i}" for i in range(25, 40))


def test_status_reports_missing_pieces(unit_file: Path) -> None:
    fake = FakeSystemd()

    report = _status(fake)

    assert report.installed is False
    assert report.active == "inactive"
    assert report.linger is False
    problems = " | ".join(report.problems)
    assert "not installed" in problems
    assert "not running" in problems
    assert "sudo loginctl enable-linger alice" in problems


def test_status_active_without_linger_is_degraded(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)
    fake.linger = False

    report = _status(fake)

    assert [p for p in report.problems if "lingering" in p]
    assert len(report.problems) == 1


def test_status_unknown_linger_counts_as_problem(unit_file: Path) -> None:
    fake = FakeSystemd()
    _install(fake)
    fake.linger_query_rc = 1

    report = _status(fake)

    assert report.linger is None
    assert "linger: unknown" in report.render()
    assert report.problems


def test_status_survives_unavailable_journal(unit_file: Path) -> None:
    fake = FakeSystemd()
    fake.journal_rc = 1

    report = _status(fake)

    assert report.journal is None
    assert "journal: unavailable" in report.render()


def test_status_ignores_junk_state_words(unit_file: Path) -> None:
    fake = FakeSystemd()
    fake.active = "\x1b[31mEVIL"

    assert _status(fake).active == "unknown"


def test_status_fails_closed_without_user_manager(unit_file: Path) -> None:
    fake = FakeSystemd()
    fake.user_manager_ok = False

    with pytest.raises(UnsupportedEnvironmentError):
        _status(fake)


# --- default runner and host ---------------------------------------------------------------


def test_run_command_uses_argv_list_timeout_and_no_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return _done(argv, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    _REAL_RUN_COMMAND(["systemctl", "--user", "daemon-reload"])

    assert captured["argv"] == ["systemctl", "--user", "daemon-reload"]
    assert captured["timeout"] > 0
    assert not captured.get("shell")


def test_detect_host_reports_current_user() -> None:
    host = user_service.detect_host()
    assert host.uid == os.getuid()
    assert re.fullmatch(r"[^\s]+", host.user)
