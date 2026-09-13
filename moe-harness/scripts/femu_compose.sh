#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
femu_root="${FEMU_SOURCE_DIR:-${repo_root}/_deps/FEMU-MoE}"

if [[ ! -f "${femu_root}/compose.yaml" ]]; then
    echo "femu_compose: ${femu_root}/compose.yaml is missing" >&2
    echo "run ${repo_root}/scripts/setup_femu.sh first" >&2
    exit 1
fi

export FEMU_GUEST_DIR="${FEMU_GUEST_DIR:-${repo_root}/images}"
export FEMU_DATA_DIR="${FEMU_DATA_DIR:-${repo_root}/runs/femu}"
mkdir -p "${FEMU_GUEST_DIR}" "${FEMU_DATA_DIR}"

# Run from the FEMU source tree instead of relying on --project-directory. The
# latter is unavailable in old Compose installations and can be misparsed as a
# top-level Docker flag when the Compose CLI plugin is absent.
cd "${femu_root}"

if docker compose version >/dev/null 2>&1; then
    exec docker compose -f compose.yaml "$@"
fi

if command -v docker-compose >/dev/null 2>&1; then
    exec docker-compose -f compose.yaml "$@"
fi

echo "femu_compose: Docker Compose is not installed" >&2
echo "install the Docker Compose plugin, or the legacy docker-compose command" >&2
exit 1
