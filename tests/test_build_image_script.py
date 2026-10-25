"""Tests for `scripts/build-image.sh`, run against fake `podman`/`systemctl` binaries.

The fakes only log their arguments; the real tools are never reachable because `PATH`
points at a directory holding nothing but the fakes and the few coreutils the script uses.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "build-image.sh"

_COREUTILS = ("dirname", "basename", "mktemp", "cat", "chmod", "mv", "rm", "mkdir")

_FAKE_PODMAN = """#!/bin/sh
printf 'podman %s\\n' "$*" >> "$FAKE_LOG"
printf 'cwd %s\\n' "$(pwd -P)" >> "$FAKE_LOG"
exit "${FAKE_PODMAN_STATUS:-0}"
"""

_FAKE_SYSTEMCTL = """#!/bin/sh
printf 'systemctl %s\\n' "$*" >> "$FAKE_LOG"
case "$*" in
*is-active*) exit "${FAKE_ACTIVE_STATUS:-0}" ;;
esac
exit 0
"""


class Env:
    """A hermetic environment for one script run."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.home = root / "home"
        self.log = root / "calls.log"
        self.bin.mkdir(parents=True)
        self.home.mkdir()
        self.log.write_text("")
        for tool in _COREUTILS:
            real = shutil.which(tool)
            assert real is not None
            (self.bin / tool).symlink_to(real)

    def add_fake(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def run(
        self, script: Path, *args: str, extra_env: dict[str, str] | None = None, cwd: Path
    ) -> subprocess.CompletedProcess[str]:
        bash = shutil.which("bash")
        assert bash is not None
        env = {
            "PATH": str(self.bin),
            "HOME": str(self.home),
            "FAKE_LOG": str(self.log),
            **(extra_env or {}),
        }
        return subprocess.run(
            [bash, str(script), *args],
            env=env,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    @property
    def unit_dir(self) -> Path:
        return self.home / ".config" / "systemd" / "user"


@pytest.fixture
def env(tmp_path: Path) -> Env:
    environment = Env(tmp_path / "env")
    environment.add_fake("podman", _FAKE_PODMAN)
    environment.add_fake("systemctl", _FAKE_SYSTEMCTL)
    return environment


def _install_script_copy(base: Path) -> Path:
    """Place a copy of the script at `<base>/scripts/build-image.sh`, as in a checkout."""
    target = base / "scripts" / "build-image.sh"
    target.parent.mkdir(parents=True)
    shutil.copy(SCRIPT, target)
    target.chmod(0o755)
    return target


def test_script_is_executable() -> None:
    assert SCRIPT.stat().st_mode & stat.S_IXUSR


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_script_passes_shellcheck() -> None:
    result = subprocess.run(
        ["shellcheck", str(SCRIPT)], capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode == 0, result.stdout


def test_build_runs_podman_in_repo_root_regardless_of_cwd(env: Env, tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    script = _install_script_copy(checkout)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    result = env.run(script, cwd=elsewhere, extra_env={"FAKE_ACTIVE_STATUS": "1"})

    assert result.returncode == 0, result.stderr
    calls = env.calls()
    assert calls[0] == (
        "podman build --format docker --pull=newer -f deploy/Containerfile "
        "-t localhost/carchive:latest ."
    )
    assert calls[1] == f"cwd {checkout.resolve()}"
    assert "podman image prune -f" in calls


def test_build_restarts_service_only_when_active(env: Env, tmp_path: Path) -> None:
    script = _install_script_copy(tmp_path / "checkout")

    active = env.run(script, cwd=tmp_path, extra_env={"FAKE_ACTIVE_STATUS": "0"})
    assert active.returncode == 0, active.stderr
    active_calls = env.calls()
    assert "systemctl --user is-active --quiet carchive.service" in active_calls
    assert "systemctl --user restart carchive.service" in active_calls
    build_index = next(i for i, c in enumerate(active_calls) if c.startswith("podman build"))
    restart_index = active_calls.index("systemctl --user restart carchive.service")
    prune_index = active_calls.index("podman image prune -f")
    assert build_index < restart_index < prune_index

    env.log.write_text("")
    inactive = env.run(script, cwd=tmp_path, extra_env={"FAKE_ACTIVE_STATUS": "3"})
    assert inactive.returncode == 0, inactive.stderr
    inactive_calls = env.calls()
    assert "systemctl --user is-active --quiet carchive.service" in inactive_calls
    assert "systemctl --user restart carchive.service" not in inactive_calls
    assert "podman image prune -f" in inactive_calls


def test_failed_build_neither_restarts_nor_prunes(env: Env, tmp_path: Path) -> None:
    script = _install_script_copy(tmp_path / "checkout")

    result = env.run(script, cwd=tmp_path, extra_env={"FAKE_PODMAN_STATUS": "125"})

    assert result.returncode != 0
    calls = env.calls()
    assert "systemctl --user restart carchive.service" not in calls
    assert "podman image prune -f" not in calls


@pytest.mark.parametrize("missing", ["podman", "systemctl"])
def test_missing_tool_exits_2_with_message(env: Env, tmp_path: Path, missing: str) -> None:
    (env.bin / missing).unlink()
    script = _install_script_copy(tmp_path / "checkout")

    result = env.run(script, cwd=tmp_path)

    assert result.returncode == 2
    assert missing in result.stderr
    assert env.calls() == []


def test_missing_systemctl_exits_2_for_timer_modes(env: Env, tmp_path: Path) -> None:
    (env.bin / "systemctl").unlink()
    script = _install_script_copy(tmp_path / "checkout")

    for flag in ("--install-timer", "--uninstall-timer"):
        result = env.run(script, flag, cwd=tmp_path)
        assert result.returncode == 2
        assert "systemctl" in result.stderr
    assert not env.unit_dir.exists()


@pytest.mark.parametrize("args", [["--bogus"], ["--install-timer", "extra"], [""], ["-h"]])
def test_unknown_arguments_print_usage_and_exit_2(
    env: Env, tmp_path: Path, args: list[str]
) -> None:
    script = _install_script_copy(tmp_path / "checkout")

    result = env.run(script, *args, cwd=tmp_path)

    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert env.calls() == []


def test_install_timer_writes_units_and_enables_timer(env: Env, tmp_path: Path) -> None:
    script = _install_script_copy(tmp_path / "checkout")

    result = env.run(script, "--install-timer", cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    service = (env.unit_dir / "carchive-image-build.service").read_text()
    timer = (env.unit_dir / "carchive-image-build.timer").read_text()
    assert "Type=oneshot" in service.splitlines()
    assert f'ExecStart="{script.resolve()}"' in service.splitlines()
    for line in ("OnCalendar=weekly", "Persistent=true", "RandomizedDelaySec=1h"):
        assert line in timer.splitlines()
    assert "WantedBy=timers.target" in timer.splitlines()
    assert env.calls() == [
        "systemctl --user daemon-reload",
        "systemctl --user enable --now carchive-image-build.timer",
    ]
    assert not [p for p in env.unit_dir.iterdir() if ".service." in p.name or ".timer." in p.name]

    again = env.run(script, "--install-timer", cwd=tmp_path)
    assert again.returncode == 0, again.stderr
    assert (env.unit_dir / "carchive-image-build.service").read_text() == service


def test_install_timer_quotes_spaces_percent_and_dollar(env: Env, tmp_path: Path) -> None:
    script = _install_script_copy(tmp_path / "my checkout 100% $HOME")

    result = env.run(script, "--install-timer", cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    service = (env.unit_dir / "carchive-image-build.service").read_text()
    expected_path = str(script.resolve()).replace("%", "%%").replace("$", "$$")
    assert f'ExecStart="{expected_path}"' in service.splitlines()
    assert "100%% $$HOME" in service


def test_install_timer_does_not_overwrite_a_symlink(env: Env, tmp_path: Path) -> None:
    script = _install_script_copy(tmp_path / "checkout")
    env.unit_dir.mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    (env.unit_dir / "carchive-image-build.service").symlink_to(victim)

    result = env.run(script, "--install-timer", cwd=tmp_path)

    assert result.returncode != 0
    assert "symlink" in result.stderr
    assert victim.read_text() == "keep me"
    assert (env.unit_dir / "carchive-image-build.service").is_symlink()
    assert env.calls() == []


def test_uninstall_timer_disables_and_removes_files(env: Env, tmp_path: Path) -> None:
    script = _install_script_copy(tmp_path / "checkout")
    assert env.run(script, "--install-timer", cwd=tmp_path).returncode == 0
    env.log.write_text("")

    result = env.run(script, "--uninstall-timer", cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert list(env.unit_dir.iterdir()) == []
    assert env.calls() == [
        "systemctl --user disable --now carchive-image-build.timer",
        "systemctl --user daemon-reload",
    ]
