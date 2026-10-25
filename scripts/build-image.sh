#!/usr/bin/env bash
# Build the Carchive container image locally and, optionally, keep it fresh with a
# weekly systemd user timer.
#
#   build-image.sh                  build localhost/carchive:latest, restart carchive.service
#                                   if it is active, prune dangling images
#   build-image.sh --install-timer  install and enable a weekly rebuild (user units)
#   build-image.sh --uninstall-timer
#                                   disable the timer and remove its unit files
#
# Exit status: 0 on success, 1 on failure, 2 on usage errors or a missing tool.
set -euo pipefail

IMAGE="localhost/carchive:latest"
SERVICE="carchive.service"
BUILD_UNIT="carchive-image-build.service"
BUILD_TIMER="carchive-image-build.timer"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
script_path="${script_dir}/$(basename -- "${BASH_SOURCE[0]}")"
repo_root="$(dirname -- "${script_dir}")"

usage() {
    cat >&2 <<'EOF'
usage: build-image.sh [--install-timer | --uninstall-timer]

  (no argument)       build the image, restart carchive.service if active
  --install-timer     install and enable a weekly rebuild (systemd user timer)
  --uninstall-timer   disable the timer and remove its unit files
EOF
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required tool '$1' not found in PATH" >&2
        exit 2
    fi
}

unit_dir() {
    if [ -z "${HOME:-}" ]; then
        echo "error: HOME is not set" >&2
        exit 2
    fi
    printf '%s\n' "${HOME}/.config/systemd/user"
}

# Quote a path as one systemd ExecStart word: backslash and double quote are escaped
# inside the quotes, '%' and '$' are doubled so systemd does not expand them.
systemd_quote() {
    local value="$1"
    case "${value}" in
    *$'\n'*)
        echo "error: path contains a newline: refusing to write a unit file" >&2
        exit 1
        ;;
    esac
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//%/%%}"
    value="${value//\$/\$\$}"
    printf '"%s"' "${value}"
}

# Write stdin to $1 atomically; refuse to touch an existing symlink.
write_unit_file() {
    local target="$1" tmp
    if [ -L "${target}" ]; then
        echo "error: ${target} is a symlink, not overwriting it" >&2
        exit 1
    fi
    tmp="$(mktemp "${target}.XXXXXX")"
    if ! { cat >"${tmp}" && chmod 0644 "${tmp}" && mv -f -- "${tmp}" "${target}"; }; then
        rm -f -- "${tmp}"
        echo "error: could not write ${target}" >&2
        exit 1
    fi
}

build() {
    require_tool podman
    require_tool systemctl
    cd -- "${repo_root}"
    podman build --format docker --pull=newer -f deploy/Containerfile -t "${IMAGE}" .
    if systemctl --user is-active --quiet "${SERVICE}"; then
        echo "restarting ${SERVICE}"
        systemctl --user restart "${SERVICE}"
    fi
    podman image prune -f
}

install_timer() {
    require_tool systemctl
    local dir exec_start
    dir="$(unit_dir)"
    exec_start="$(systemd_quote "${script_path}")"
    mkdir -p -- "${dir}"

    write_unit_file "${dir}/${BUILD_UNIT}" <<EOF
[Unit]
Description=Rebuild the Carchive container image

[Service]
Type=oneshot
ExecStart=${exec_start}
EOF

    write_unit_file "${dir}/${BUILD_TIMER}" <<EOF
[Unit]
Description=Weekly rebuild of the Carchive container image

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

    systemctl --user daemon-reload
    systemctl --user enable --now "${BUILD_TIMER}"
    echo "installed ${BUILD_TIMER}; rebuild on demand: systemctl --user start ${BUILD_UNIT}"
}

uninstall_timer() {
    require_tool systemctl
    local dir
    dir="$(unit_dir)"
    if ! systemctl --user disable --now "${BUILD_TIMER}"; then
        echo "warning: could not disable ${BUILD_TIMER}, removing its files anyway" >&2
    fi
    rm -f -- "${dir}/${BUILD_TIMER}" "${dir}/${BUILD_UNIT}"
    systemctl --user daemon-reload
    echo "removed ${BUILD_TIMER}"
}

case "$#:${1:-}" in
0:)
    build
    ;;
1:--install-timer)
    install_timer
    ;;
1:--uninstall-timer)
    uninstall_timer
    ;;
*)
    usage
    exit 2
    ;;
esac
