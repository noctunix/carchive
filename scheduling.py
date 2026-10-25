"""Installs, removes and reports the periodic `fetch` run.

Two backends: a systemd user timer (Linux with a reachable user manager) and
a managed block in the user's crontab (FreeBSD, or Linux without systemd).
The timer is only chosen automatically when lingering is enabled, because
without it the user manager - and the timer with it - stops at logout.
"""

from __future__ import annotations

import getpass
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

UNIT_NAME = "carchive-fetch"
CRON_BEGIN = "# BEGIN carchive-fetch (managed by 'schedule'; edits inside are overwritten)"
CRON_END = "# END carchive-fetch"
VALID_INTERVALS = (5, 10, 15, 20, 30, 60)

Runner = Callable[[Sequence[str], str | None], "subprocess.CompletedProcess[str]"]


def run_command(argv: Sequence[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), input=stdin, text=True, capture_output=True, check=False)


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "carchive"


def systemd_user_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


@dataclass(frozen=True)
class FetchCommand:
    workdir: Path
    argv: tuple[str, ...]

    def shell(self) -> str:
        return f"cd {shlex.quote(str(self.workdir))} && {shlex.join(self.argv)}"


def fetch_command(script: Path, config: Path, log_file: Path | None) -> FetchCommand:
    """Builds the command a scheduler runs, with absolute paths only: cron and
    systemd start with a minimal PATH."""
    uv = shutil.which("uv")
    argv = [uv, "run", "--frozen", "python", script.name] if uv else [sys.executable, str(script)]
    argv += ["--config", str(config)]
    if log_file is not None:
        argv += ["--log-file", str(log_file)]
    argv.append("fetch")
    return FetchCommand(script.parent, tuple(argv))


def cron_block(command: FetchCommand, interval_min: int, offset_min: int) -> str:
    """A crontab block that runs `command` every `interval_min` minutes,
    shifted by `offset_min` so runs do not all hit the portal on the hour."""
    minutes = ",".join(str(m) for m in range(offset_min % interval_min, 60, interval_min))
    return f"{CRON_BEGIN}\n{minutes} * * * * {command.shell()}\n{CRON_END}\n"


def merge_crontab(existing: str, block: str | None) -> tuple[str, list[str]]:
    """Replaces the managed block in `existing` with `block` (or removes it if
    `block` is None). Also returns the lines outside the block that run the
    sampler themselves, e.g. a hand-written entry, which would double up."""
    kept: list[str] = []
    foreign: list[str] = []
    inside = False
    for line in existing.splitlines():
        if line.strip() == CRON_BEGIN:
            inside = True
            continue
        if inside:
            if line.strip() == CRON_END:
                inside = False
            continue
        kept.append(line)
        stripped = line.strip()
        if not stripped.startswith("#") and "eu_data_act_sampler.py" in stripped:
            foreign.append(stripped)
    while kept and not kept[-1].strip():
        kept.pop()
    text = "\n".join(kept)
    if text:
        text += "\n"
    if block:
        text += ("\n" if text else "") + block
    return text, foreign


def _systemd_quote(arg: str) -> str:
    escaped = arg.replace("%", "%%")
    if re.search(r"[\s\"'\\]", escaped):
        escaped = '"' + escaped.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return escaped


def systemd_units(command: FetchCommand, interval_min: int) -> dict[str, str]:
    exec_start = " ".join(_systemd_quote(a) for a in command.argv)
    delay_s = min(180, interval_min * 60 // 4)
    service = (
        "[Unit]\n"
        "Description=Carchive: fetch EU Data Act deliveries\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"WorkingDirectory={_systemd_quote(str(command.workdir))}\n"
        f"ExecStart={exec_start}\n"
    )
    timer = (
        "[Unit]\n"
        f"Description=Run {UNIT_NAME} every {interval_min} minutes\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar=*:0/{interval_min}\n"
        f"RandomizedDelaySec={delay_s}\n"
        "FixedRandomDelay=true\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return {f"{UNIT_NAME}.service": service, f"{UNIT_NAME}.timer": timer}


def systemd_user_available(run: Runner) -> bool:
    if shutil.which("systemctl") is None:
        return False
    return run(["systemctl", "--user", "show-environment"], None).returncode == 0


def linger_enabled(run: Runner) -> bool:
    result = run(["loginctl", "show-user", getpass.getuser(), "--property=Linger", "--value"], None)
    return result.returncode == 0 and result.stdout.strip() == "yes"


def read_crontab(run: Runner) -> str:
    result = run(["crontab", "-l"], None)
    # "no crontab for <user>" is a non-zero exit with nothing to keep.
    return result.stdout if result.returncode == 0 else ""


def write_crontab(run: Runner, text: str) -> None:
    result = run(["crontab", "-"], text)
    if result.returncode != 0:
        raise RuntimeError(f"crontab rejected the update: {result.stderr.strip()}")


def _systemctl(run: Runner, *args: str) -> None:
    result = run(["systemctl", "--user", *args], None)
    if result.returncode != 0:
        raise RuntimeError(f"systemctl --user {' '.join(args)} failed: {result.stderr.strip()}")


def _remove_systemd(run: Runner, unit_dir: Path) -> bool:
    paths = [unit_dir / name for name in (f"{UNIT_NAME}.timer", f"{UNIT_NAME}.service")]
    if not any(p.exists() for p in paths):
        return False
    run(["systemctl", "--user", "disable", "--now", f"{UNIT_NAME}.timer"], None)
    for p in paths:
        p.unlink(missing_ok=True)
    run(["systemctl", "--user", "daemon-reload"], None)
    return True


def _remove_cron(run: Runner) -> bool:
    existing = read_crontab(run)
    if CRON_BEGIN not in existing:
        return False
    text, _ = merge_crontab(existing, None)
    write_crontab(run, text)
    return True


def install(
    command_for: Callable[[Path | None], FetchCommand],
    backend: str,
    interval_min: int,
    run: Runner = run_command,
    unit_dir: Path | None = None,
    report: Callable[[str], None] = print,
) -> int:
    """Installs the schedule with `backend` ("auto", "systemd" or "cron"),
    replacing an earlier installation of either backend. `command_for` gets
    the log file to use (None when output goes to the journal)."""
    if interval_min not in VALID_INTERVALS:
        report(f"interval must be one of {VALID_INTERVALS} minutes")
        return 2
    unit_dir = unit_dir or systemd_user_dir()
    has_systemd = systemd_user_available(run)
    lingering = has_systemd and linger_enabled(run)
    if backend == "auto":
        backend = "systemd" if lingering else "cron"
        if has_systemd and not lingering:
            report(
                "systemd user timers stop at logout without lingering; using cron instead."
                f" For the timer: 'sudo loginctl enable-linger {getpass.getuser()}', then"
                " 'schedule install' again."
            )
    if backend == "systemd" and not has_systemd:
        report("no systemd user manager reachable; use --backend cron")
        return 2
    if backend == "systemd" and not lingering:
        report(
            "refusing the systemd timer without lingering: it would stop at logout."
            f" Enable it with 'sudo loginctl enable-linger {getpass.getuser()}' or use cron."
        )
        return 2

    if backend == "systemd":
        _remove_cron(run)
        unit_dir.mkdir(parents=True, exist_ok=True)
        for name, text in systemd_units(command_for(None), interval_min).items():
            (unit_dir / name).write_text(text, encoding="utf-8")
        _systemctl(run, "daemon-reload")
        _systemctl(run, "enable", "--now", f"{UNIT_NAME}.timer")
        report(f"installed systemd user timer {UNIT_NAME}.timer (every {interval_min} min)")
        report(f"logs: journalctl --user -u {UNIT_NAME}.service")
    else:
        _remove_systemd(run, unit_dir)
        log_file = state_dir() / "fetch.log"
        offset = random.randrange(1, min(interval_min, 15))
        block = cron_block(command_for(log_file), interval_min, offset)
        text, _ = merge_crontab(read_crontab(run), block)
        write_crontab(run, text)
        report(f"installed crontab entry (every {interval_min} min, log: {log_file})")

    _, foreign = merge_crontab(read_crontab(run), None)
    for line in foreign:
        report(f"warning: your crontab also runs the sampler itself, remove it: {line}")
    return 0


def remove(
    run: Runner = run_command,
    unit_dir: Path | None = None,
    report: Callable[[str], None] = print,
) -> int:
    removed_systemd = _remove_systemd(run, unit_dir or systemd_user_dir())
    removed_cron = _remove_cron(run)
    if removed_systemd:
        report(f"removed systemd user timer {UNIT_NAME}.timer")
    if removed_cron:
        report("removed crontab entry")
    if not (removed_systemd or removed_cron):
        report("nothing installed")
    return 0


def status(
    run: Runner = run_command,
    unit_dir: Path | None = None,
    report: Callable[[str], None] = print,
) -> int:
    unit_dir = unit_dir or systemd_user_dir()
    found = False
    if (unit_dir / f"{UNIT_NAME}.timer").exists():
        found = True
        result = run(
            ["systemctl", "--user", "list-timers", f"{UNIT_NAME}.timer", "--no-pager"], None
        )
        report(result.stdout.strip() or "systemd timer installed, but systemctl gave no status")
    crontab = read_crontab(run)
    if CRON_BEGIN in crontab:
        found = True
        block = crontab[crontab.index(CRON_BEGIN) :]
        report(block[: block.index(CRON_END) + len(CRON_END)])
    _, foreign = merge_crontab(crontab, None)
    for line in foreign:
        found = True
        report(f"unmanaged crontab entry: {line}")
    if not found:
        report("no schedule installed")
    return 0
