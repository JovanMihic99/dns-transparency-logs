#!/usr/bin/env bash

# Shared Docker permission handling for all LoKey scripts.

if [[ -z "${LOKEY_DOCKER_INITIALIZED:-}" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: Docker is not installed." >&2
        return 1 2>/dev/null || exit 1
    fi

    LOKEY_DOCKER_BIN="$(type -P docker)"

    if "$LOKEY_DOCKER_BIN" info >/dev/null 2>&1; then
        LOKEY_DOCKER_USE_SUDO=0
    else
        echo "Docker requires elevated permissions. Requesting sudo..." >&2

        sudo -v || {
            echo "ERROR: sudo authentication failed." >&2
            return 1 2>/dev/null || exit 1
        }

        if ! sudo "$LOKEY_DOCKER_BIN" info >/dev/null 2>&1; then
            echo "ERROR: Docker daemon is unavailable." >&2
            return 1 2>/dev/null || exit 1
        fi

        LOKEY_DOCKER_USE_SUDO=1
    fi

    export LOKEY_DOCKER_USE_SUDO
    export LOKEY_DOCKER_BIN
    export LOKEY_DOCKER_INITIALIZED=1
fi

# Override Docker with a permission-aware function.
docker() {
    if [[ "${LOKEY_DOCKER_USE_SUDO:-0}" == "1" ]]; then
        command sudo "$LOKEY_DOCKER_BIN" "$@"
    else
        command "$LOKEY_DOCKER_BIN" "$@"
    fi
}
