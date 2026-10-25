"""Install, remove and inspect Carchive as a systemd user service.

The unit runs `carchive serve` (web GUI and collector in one process). It carries no
environment variables, so the service always uses the default config, secrets and data
locations of the user that installed it. Lingering is required for the unit to survive
logout; `install` tries to enable it and `status` reports it.

All subprocesses go through an injectable runner (argv list, never a shell, always with a
timeout), so tests never touch the real `systemctl`, `loginctl` or `journalctl`.
"""

from __future__ import annotations

import contextlib
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

UNIT_NAME = "carchive.service"
JOURNAL_LINES = 15

_COMMAND_TIMEOUT_S = 60
_DETAIL_MAX_CHARS = 200
_README_HINT = (
    "see 'Running Carchive' in the README for the other ways to run it "
    "(rc script on FreeBSD, Podman)"
)
_PLAIN_WORD = re.compile(r"[A-Za-z0-9_./:+,@=%$-]+")
_STATE_WORD = re.compile(r"[a-z-]{1,32}")

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]
Output = Callable[[str], None]


class UserServiceError(Exception):
    """Raised when a service operation fails; the message is safe to show to the user."""


class UnsupportedEnvironmentError(UserServiceError):
    """Raised when this host cannot run a systemd user service (nothing was changed)."""


@dataclass(frozen=True)
class Host:
    """The facts about the host that decide whether a user service can be managed.

    Attributes:
        uid: numeric user id of the current process.
        user: login name belonging to `uid`.
        systemctl: path of `systemctl`, or `None` if it is not on `PATH`.
    """

    uid: int
    user: str
    systemctl: str | None


@dataclass(frozen=True)
class ServiceStatus:
    """What `status` found out about the installed service.

    Attributes:
        unit_path: where the unit file lives (or would live).
        installed: whether the unit file exists.
        enabled: `systemctl is-enabled` state word, `unknown` if unreadable.
        active: `systemctl is-active` state word, `unknown` if unreadable.
        linger: whether lingering is on, `None` if it could not be determined.
        user: login name the linger state belongs to.
        url: address the web GUI listens on, if known.
        journal: the last journal lines, unmodified, or `None` if unavailable.
    """

    unit_path: Path
    installed: bool
    enabled: str
    active: str
    linger: bool | None
    user: str
    url: str | None
    journal: tuple[str, ...] | None

    @property
    def problems(self) -> list[str]:
        """Return one line per reason the service is not fully working."""
        found: list[str] = []
        if not self.installed:
            found.append("unit is not installed (run: carchive service install)")
        if self.active != "active":
            found.append(f"service is not running (state: {self.active})")
        if self.linger is not True:
            found.append(
                f"lingering is off, the service stops at logout (run: {linger_command(self.user)})"
            )
        return found

    def render(self) -> list[str]:
        """Return the report lines for stdout; journal lines come last and unmodified."""
        lines = [
            f"unit: {'installed' if self.installed else 'not installed'} ({self.unit_path})",
            f"enabled: {self.enabled}",
            f"active: {self.active}",
            f"linger: {_linger_word(self.linger)}",
        ]
        if self.url is not None:
            lines.append(f"url: {self.url}")
        if self.journal is None:
            lines.append("journal: unavailable")
        else:
            lines.append(f"journal (last {JOURNAL_LINES} lines):")
            lines.extend(self.journal)
        return lines


def run_command(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run one command without a shell and with a timeout.

    Args:
        argv: the program and its arguments.

    Returns:
        The completed process with captured, text-decoded output.

    Raises:
        subprocess.TimeoutExpired: if the command runs longer than the timeout.
        OSError: if the program cannot be started.
    """
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        stdin=subprocess.DEVNULL,
        timeout=_COMMAND_TIMEOUT_S,
    )


def detect_host() -> Host:
    """Collect the facts about the current host and user.

    Returns:
        The detected `Host`.

    Raises:
        UnsupportedEnvironmentError: if the user name cannot be determined.
    """
    uid = os.getuid()
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError as exc:
        raise UnsupportedEnvironmentError(f"cannot determine the user name for uid {uid}") from exc
    systemctl = shutil.which("systemctl") if sys.platform.startswith("linux") else None
    return Host(uid=uid, user=user, systemctl=systemctl)


def linger_command(user: str) -> str:
    """Return the command that enables lingering for `user` with root privileges."""
    return f"sudo loginctl enable-linger {shlex.quote(user)}"


def unit_path() -> Path:
    """Return where the user unit is installed.

    Returns:
        `$XDG_CONFIG_HOME/systemd/user/carchive.service`, or the same below `~/.config`
        when `XDG_CONFIG_HOME` is unset or not absolute.
    """
    configured = os.environ.get("XDG_CONFIG_HOME")
    base = Path(configured).expanduser() if configured else None
    if base is None or not base.is_absolute():
        base = Path.home() / ".config"
    return base / "systemd" / "user" / UNIT_NAME


def systemd_quote(word: str) -> str:
    """Quote one word for an `ExecStart=` command line.

    Args:
        word: a single argument.

    Returns:
        The word as systemd parses it back to `word`: `%` doubled (specifiers), `$`
        doubled (variable substitution), and double-quoted with backslash and
        quote escaped when it contains anything but plain path characters.

    Raises:
        UserServiceError: if the word is empty or contains control characters (which could
            inject further unit lines).
    """
    if not word or any(ord(char) < 0x20 or ord(char) == 0x7F for char in word):
        raise UserServiceError("the program path is empty or contains control characters")
    if _PLAIN_WORD.fullmatch(word):
        return word.replace("%", "%%").replace("$", "$$")
    escaped = word.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f'"{escaped}"'


def exec_start_line(command: Sequence[str]) -> str:
    """Build the value of `ExecStart=` for `command` followed by `serve`.

    Args:
        command: the program (absolute path) and any fixed leading arguments.

    Returns:
        The quoted command line.

    Raises:
        UserServiceError: if the program is not an absolute path or a word is unusable.
    """
    if not command or not Path(command[0]).is_absolute():
        raise UserServiceError("the program path must be absolute")
    return " ".join(systemd_quote(word) for word in [*command, "serve"])


def render_unit(exec_start: str) -> str:
    """Render the unit file text.

    Args:
        exec_start: the complete, already quoted `ExecStart=` value.

    Returns:
        The unit file content.
    """
    return (
        "[Unit]\n"
        "Description=Carchive EU Data Act collector\n"
        "\n"
        "[Service]\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\n"
        "RestartSec=30\n"
        "TimeoutStopSec=30\n"
        "UMask=0077\n"
        "NoNewPrivileges=yes\n"
        "LockPersonality=yes\n"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def resolve_exec_command(
    argv0: str | None = None,
    executable: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str]:
    """Work out the command that starts the running Carchive.

    Args:
        argv0: how this process was invoked; defaults to `sys.argv[0]`.
        executable: the Python interpreter; defaults to `sys.executable`.
        which: `PATH` lookup used when `argv0` has no directory part.

    Returns:
        The absolute path of the `carchive` program if it was started through it, else
        the interpreter followed by `-m carchive`.

    Raises:
        UserServiceError: if neither form yields an absolute path.
    """
    argv0 = sys.argv[0] if argv0 is None else argv0
    executable = sys.executable if executable is None else executable
    if argv0:
        found = argv0 if os.sep in argv0 else which(argv0)
        if found:
            # Not resolve(): a symlinked install path (e.g. ~/.local/bin) stays stable
            # across upgrades.
            path = Path(os.path.abspath(found))
            if path.name == "carchive" and path.is_file() and os.access(path, os.X_OK):
                return [str(path)]
    if not executable or not Path(executable).is_absolute():
        raise UserServiceError("cannot determine the absolute path of the running carchive")
    return [executable, "-m", "carchive"]


def install(
    *,
    start: bool = True,
    out: Output,
    err: Output,
    runner: Runner | None = None,
    host: Host | None = None,
    command: Sequence[str] | None = None,
) -> None:
    """Write the unit, register it with the user manager and try to enable lingering.

    Running it again with the same program is a no-op apart from making sure the unit is
    enabled (and started); a changed unit is rewritten and a running service restarted.
    A failed linger activation is only a warning, because the service itself is installed.

    Args:
        start: start the service now; otherwise it is only enabled.
        out: receives one progress line per step.
        err: receives warnings.
        runner: command runner; defaults to `run_command`.
        host: host facts; detected when omitted.
        command: program that `ExecStart=` runs before `serve`; resolved from the running
            process when omitted.

    Raises:
        UnsupportedEnvironmentError: if there is no usable systemd user manager, or the
            process runs as root. Nothing is written in that case.
        UserServiceError: if the unit cannot be written or a systemctl step fails.
    """
    run = runner or run_command
    host = host or detect_host()
    _preflight(host, run)

    content = render_unit(exec_start_line(command or resolve_exec_command()))
    path = unit_path()
    previous = _read_unit(path)
    changed = previous != content
    was_active = _state(run, "is-active") == "active"

    if changed:
        _write_atomic(path, content)
        out(f"wrote {path}" if previous is None else f"updated {path}")
    else:
        out(f"unit unchanged: {path}")

    _systemctl(run, "daemon-reload")
    out("reloaded the user manager")
    if start:
        _systemctl(run, "enable", "--now", UNIT_NAME)
    else:
        _systemctl(run, "enable", UNIT_NAME)
    out(f"enabled {UNIT_NAME}" + (" and started it" if start else ""))
    if changed and was_active:
        if start:
            _systemctl(run, "restart", UNIT_NAME)
            out(f"restarted {UNIT_NAME} to apply the changed unit")
        else:
            out(f"{UNIT_NAME} still runs the old unit; run: systemctl --user restart {UNIT_NAME}")

    _ensure_linger(run, host.user, out, err)


def uninstall(
    *,
    out: Output,
    runner: Runner | None = None,
    host: Host | None = None,
) -> None:
    """Stop and disable the service and delete its unit file.

    Lingering is left as it is, since other user services may rely on it. A missing unit
    is not an error.

    Args:
        out: receives one progress line per step.
        runner: command runner; defaults to `run_command`.
        host: host facts; detected when omitted.

    Raises:
        UnsupportedEnvironmentError: if there is no usable systemd user manager, or the
            process runs as root.
        UserServiceError: if a systemctl step or the file removal fails.
    """
    run = runner or run_command
    host = host or detect_host()
    _preflight(host, run)

    path = unit_path()
    if not (path.is_file() or path.is_symlink()):
        out(f"{UNIT_NAME} is not installed, nothing to do")
        return

    _systemctl(run, "disable", "--now", UNIT_NAME)
    out(f"stopped and disabled {UNIT_NAME}")
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise UserServiceError(f"cannot remove {path}: {exc.strerror or exc}") from exc
    out(f"removed {path}")
    _systemctl(run, "daemon-reload")
    out("reloaded the user manager")
    out("lingering left unchanged (other user services may need it)")


def status(
    *,
    url: str | None = None,
    runner: Runner | None = None,
    host: Host | None = None,
) -> ServiceStatus:
    """Collect the state of the service, lingering and the recent journal.

    Args:
        url: address of the web GUI to include in the report, if known.
        runner: command runner; defaults to `run_command`.
        host: host facts; detected when omitted.

    Returns:
        The collected `ServiceStatus`.

    Raises:
        UnsupportedEnvironmentError: if there is no usable systemd user manager, or the
            process runs as root.
        UserServiceError: if a state query cannot be run at all.
    """
    run = runner or run_command
    host = host or detect_host()
    _preflight(host, run)

    path = unit_path()
    journal: tuple[str, ...] | None = None
    result = _try(
        run, ["journalctl", "--user", "-u", UNIT_NAME, "-n", str(JOURNAL_LINES), "--no-pager"]
    )
    if result is not None and result.returncode == 0:
        journal = tuple((result.stdout or "").splitlines()[-JOURNAL_LINES:])
    return ServiceStatus(
        unit_path=path,
        installed=path.is_file(),
        enabled=_state(run, "is-enabled"),
        active=_state(run, "is-active"),
        linger=_linger(run, host.user),
        user=host.user,
        url=url,
        journal=journal,
    )


def _linger_word(linger: bool | None) -> str:
    if linger is None:
        return "unknown"
    return "on" if linger else "off"


def _preflight(host: Host, run: Runner) -> None:
    if host.systemctl is None:
        raise UnsupportedEnvironmentError(f"systemctl not found; {_README_HINT}")
    if host.uid == 0:
        raise UnsupportedEnvironmentError(
            "refusing to manage a user service as root; run this as the unprivileged "
            "user that owns the Carchive data"
        )
    result = _call(run, ["systemctl", "--user", "show-environment"])
    if result.returncode != 0:
        raise UnsupportedEnvironmentError(
            "no systemd user manager reachable (not in a login session, or "
            f"XDG_RUNTIME_DIR unset); {_README_HINT}"
        )


def _call(run: Runner, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return run(argv)
    except subprocess.TimeoutExpired as exc:
        raise UserServiceError(f"`{' '.join(argv)}` timed out") from exc
    except OSError as exc:
        raise UserServiceError(
            f"cannot run {argv[0]}: {exc.strerror or type(exc).__name__}"
        ) from exc


def _try(run: Runner, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return _call(run, argv)
    except UserServiceError:
        return None


def _systemctl(run: Runner, *args: str) -> None:
    argv = ["systemctl", "--user", *args]
    result = _call(run, argv)
    if result.returncode != 0:
        lines = (result.stderr or "").strip().splitlines()
        detail = f": {lines[0][:_DETAIL_MAX_CHARS]}" if lines else ""
        raise UserServiceError(f"`{' '.join(argv)}` failed (exit {result.returncode}){detail}")


def _state(run: Runner, query: str) -> str:
    # is-enabled/is-active report the state on stdout and signal "not enabled/active" by
    # a non-zero exit, so only the word is evaluated.
    result = _call(run, ["systemctl", "--user", query, UNIT_NAME])
    words = (result.stdout or "").split()
    word = words[0] if words else ""
    return word if _STATE_WORD.fullmatch(word) else "unknown"


def _linger(run: Runner, user: str) -> bool | None:
    result = _try(run, ["loginctl", "show-user", user, "-p", "Linger"])
    if result is None or result.returncode != 0:
        return None
    for line in (result.stdout or "").splitlines():
        if line.startswith("Linger="):
            value = line.partition("=")[2].strip()
            if value in ("yes", "no"):
                return value == "yes"
    return None


def _ensure_linger(run: Runner, user: str, out: Output, err: Output) -> None:
    if _linger(run, user) is True:
        out("lingering already enabled")
        return
    result = _try(run, ["loginctl", "enable-linger", user])
    if result is not None and result.returncode == 0:
        out("enabled lingering")
        return
    err(
        "warning: could not enable lingering; the service stops when you log out.\n"
        f"warning: run: {linger_command(user)}"
    )


def _read_unit(path: Path) -> str | None:
    if path.is_symlink():
        raise UserServiceError(f"refusing to overwrite a symlink: {path}")
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise UserServiceError(f"cannot read {path}: {exc}") from exc


def _write_atomic(path: Path, content: str) -> None:
    tmp_name: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{UNIT_NAME}.")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        tmp_name = None
    except OSError as exc:
        raise UserServiceError(f"cannot write {path}: {exc.strerror or exc}") from exc
    finally:
        if tmp_name is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
