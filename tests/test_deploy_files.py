"""Static checks on the deployment artifacts under `deploy/`.

These do not build or run anything (the actual image build is a manual smoke test);
they catch regressions in the Containerfile/Quadlet/unit text itself.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from carchive.services.user_service import render_unit

REPO_ROOT = Path(__file__).parent.parent
CONTAINERFILE = REPO_ROOT / "deploy" / "Containerfile"
CONTAINERIGNORE = REPO_ROOT / ".containerignore"
QUADLET = REPO_ROOT / "deploy" / "podman" / "carchive.container"
SYSTEMD_UNIT = REPO_ROOT / "deploy" / "systemd" / "carchive.service"
FREEBSD_RC = REPO_ROOT / "deploy" / "freebsd" / "carchive"


def test_containerfile_runs_as_non_root_user() -> None:
    text = CONTAINERFILE.read_text()
    user_lines = [line for line in text.splitlines() if line.startswith("USER ")]
    assert user_lines, "Containerfile must set USER"
    assert all(line.split()[1] != "root" for line in user_lines)


def test_containerfile_has_healthcheck() -> None:
    assert "HEALTHCHECK" in CONTAINERFILE.read_text()


def test_containerfile_healthcheck_uses_the_cli_probe() -> None:
    text = CONTAINERFILE.read_text()
    healthcheck = text[text.index("HEALTHCHECK") :].split("ENTRYPOINT")[0]
    assert '"carchive", "healthcheck"' in healthcheck


def test_containerfile_has_no_add_instruction() -> None:
    lines = CONTAINERFILE.read_text().splitlines()
    assert not any(line.strip().startswith("ADD ") for line in lines)


def test_containerfile_never_copies_secrets_or_env_files() -> None:
    text = CONTAINERFILE.read_text()
    copy_lines = [line for line in text.splitlines() if line.strip().startswith("COPY ")]
    for line in copy_lines:
        assert "secrets" not in line.lower()
        assert ".env" not in line


def test_containerignore_is_an_allowlist_matching_the_containerfile() -> None:
    lines = CONTAINERIGNORE.read_text().splitlines()
    non_comment = [line for line in lines if line.strip() and not line.startswith("#")]
    assert non_comment[0] == "*", "the first rule must exclude everything else allowlists it"

    # Collect every path a non-stage COPY instruction reads from the build context.
    copy_sources: set[str] = set()
    for line in CONTAINERFILE.read_text().splitlines():
        stripped = line.strip()
        if not stripped.startswith("COPY ") or "--from=" in stripped:
            continue
        copy_sources.update(stripped.split()[1:-1])

    for pattern in non_comment[1:]:
        if not pattern.startswith("!"):
            continue
        path = pattern[1:].rstrip("/")
        assert path in copy_sources, f"{pattern!r} allows a path the Containerfile never COPYs"


def test_quadlet_publishes_loopback_only() -> None:
    text = QUADLET.read_text()
    publish_lines = [line for line in text.splitlines() if line.startswith("PublishPort=")]
    assert publish_lines, "Quadlet must publish the port"
    assert all(line.startswith("PublishPort=127.0.0.1:") for line in publish_lines)


def test_quadlet_sets_no_new_privileges() -> None:
    assert "NoNewPrivileges=true" in QUADLET.read_text().splitlines()


def test_systemd_unit_sets_restrictive_umask() -> None:
    assert "UMask=0077" in SYSTEMD_UNIT.read_text().splitlines()


def test_systemd_unit_targets_user_tool_install_binary() -> None:
    text = SYSTEMD_UNIT.read_text()
    assert "ExecStart=%h/.local/bin/carchive serve" in text


def test_systemd_unit_matches_generated_unit() -> None:
    lines = SYSTEMD_UNIT.read_text().splitlines()
    body = lines[next(i for i, line in enumerate(lines) if line.startswith("[Unit]")) :]
    assert "\n".join(body) + "\n" == render_unit("%h/.local/bin/carchive serve")


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX shell available")
def test_freebsd_rc_script_is_syntactically_valid_sh() -> None:
    result = subprocess.run(
        ["sh", "-n", str(FREEBSD_RC)], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr


def test_freebsd_rc_script_declares_rc_subr_variables() -> None:
    text = FREEBSD_RC.read_text()
    assert "carchive_enable" in text
    assert "carchive_user" in text
    assert "/var/db/carchive" in text
    assert "daemon" in text
