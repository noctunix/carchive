"""Tests for scheduling.py. No real systemctl, loginctl or crontab is called."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

import scheduling

COMMAND = scheduling.FetchCommand(
    Path("/opt/car chive"), ("/usr/bin/uv", "run", "python", "eu_data_act_sampler.py", "fetch")
)


class FakeSystem:
    """Stands in for systemctl, loginctl and crontab."""

    def __init__(self, systemd: bool, linger: bool, crontab: str = ""):
        self.systemd = systemd
        self.linger = linger
        self.crontab = crontab
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], stdin: str | None) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append(argv)
        if argv[0] == "systemctl":
            return self._result(0 if self.systemd else 1)
        if argv[0] == "loginctl":
            return self._result(0, "yes\n" if self.linger else "no\n")
        if argv[:2] == ["crontab", "-l"]:
            return self._result(0, self.crontab) if self.crontab else self._result(1)
        if argv[:2] == ["crontab", "-"]:
            self.crontab = stdin or ""
            return self._result(0)
        raise AssertionError(f"unexpected command {argv}")

    @staticmethod
    def _result(code: int, stdout: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, stdout, "")


@pytest.fixture(autouse=True)
def _systemctl_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")


def _install(system: FakeSystem, tmp_path: Path, backend: str = "auto") -> tuple[int, list[str]]:
    messages: list[str] = []
    code = scheduling.install(
        lambda _log: COMMAND, backend, 15, system, tmp_path / "units", messages.append
    )
    return code, messages


def test_cron_block_spreads_runs_over_the_hour_with_an_offset() -> None:
    block = scheduling.cron_block(COMMAND, 15, 7)
    line = block.splitlines()[1]
    assert line.startswith("7,22,37,52 * * * * cd '/opt/car chive' && /usr/bin/uv run")


def test_merge_crontab_replaces_only_the_managed_block_and_reports_foreign_entries() -> None:
    existing = (
        "MAILTO=me\n"
        "*/15 * * * * cd /x && uv run python eu_data_act_sampler.py fetch\n"
        f"{scheduling.CRON_BEGIN}\nold line\n{scheduling.CRON_END}\n"
        "0 3 * * * backup\n"
    )
    block = scheduling.cron_block(COMMAND, 15, 3)
    text, foreign = scheduling.merge_crontab(existing, block)
    assert "old line" not in text
    assert text.startswith("MAILTO=me\n")
    assert "0 3 * * * backup" in text
    assert text.endswith("\n" + block)
    assert foreign == ["*/15 * * * * cd /x && uv run python eu_data_act_sampler.py fetch"]
    removed, _ = scheduling.merge_crontab(text, None)
    assert scheduling.CRON_BEGIN not in removed
    assert "0 3 * * * backup" in removed


def test_systemd_units_escape_percent_and_spaces() -> None:
    command = scheduling.FetchCommand(Path("/a b"), ("/usr/bin/uv", "--config", "/c/50%.ini"))
    units = scheduling.systemd_units(command, 15)
    service = units["carchive-fetch.service"]
    assert 'WorkingDirectory="/a b"' in service
    assert "ExecStart=/usr/bin/uv --config /c/50%%.ini" in service
    assert "OnCalendar=*:0/15" in units["carchive-fetch.timer"]
    assert "Persistent=true" in units["carchive-fetch.timer"]


def test_auto_uses_systemd_only_with_lingering(tmp_path: Path) -> None:
    system = FakeSystem(systemd=True, linger=True)
    code, _ = _install(system, tmp_path)
    assert code == 0
    assert (tmp_path / "units" / "carchive-fetch.timer").is_file()
    assert ["systemctl", "--user", "enable", "--now", "carchive-fetch.timer"] in system.calls
    assert scheduling.CRON_BEGIN not in system.crontab


def test_auto_falls_back_to_cron_without_lingering(tmp_path: Path) -> None:
    system = FakeSystem(systemd=True, linger=False)
    code, messages = _install(system, tmp_path)
    assert code == 0
    assert scheduling.CRON_BEGIN in system.crontab
    assert not (tmp_path / "units" / "carchive-fetch.timer").exists()
    assert any("enable-linger" in m for m in messages)


def test_explicit_systemd_without_lingering_is_refused(tmp_path: Path) -> None:
    system = FakeSystem(systemd=True, linger=False)
    code, messages = _install(system, tmp_path, backend="systemd")
    assert code == 2
    assert not (tmp_path / "units").exists()
    assert scheduling.CRON_BEGIN not in system.crontab


def test_switching_backend_removes_the_other_installation(tmp_path: Path) -> None:
    system = FakeSystem(systemd=True, linger=False)
    _install(system, tmp_path)
    assert scheduling.CRON_BEGIN in system.crontab
    system.linger = True
    _install(system, tmp_path)
    assert scheduling.CRON_BEGIN not in system.crontab
    assert (tmp_path / "units" / "carchive-fetch.timer").is_file()


def test_install_warns_about_a_hand_written_entry(tmp_path: Path) -> None:
    system = FakeSystem(
        systemd=False,
        linger=False,
        crontab="*/15 * * * * cd /x && uv run python eu_data_act_sampler.py fetch\n",
    )
    code, messages = _install(system, tmp_path)
    assert code == 0
    assert any("also runs the sampler" in m for m in messages)


def test_remove_cleans_up_both_backends(tmp_path: Path) -> None:
    system = FakeSystem(systemd=True, linger=True)
    _install(system, tmp_path)
    messages: list[str] = []
    scheduling.remove(system, tmp_path / "units", messages.append)
    assert not (tmp_path / "units" / "carchive-fetch.timer").exists()
    assert messages == ["removed systemd user timer carchive-fetch.timer"]


def test_invalid_interval_is_rejected(tmp_path: Path) -> None:
    messages: list[str] = []
    code = scheduling.install(
        lambda _log: COMMAND, "cron", 7, FakeSystem(False, False), tmp_path, messages.append
    )
    assert code == 2
