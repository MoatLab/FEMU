#!/bin/bash
# Log in to a guest built by make-guest-image.sh, or run one command in it.
#
#   ./run-guest-ssh.sh                 # interactive shell
#   ./run-guest-ssh.sh sudo nvme list  # one command
#
# The run-*.sh scripts forward host port 8080 to the guest's port 22.

set -euo pipefail

IMGDIR=${IMGDIR:-${HOME:?HOME is not set}/images}
SSH_KEY=${SSH_KEY:-$IMGDIR/femu-guest-key}
SSH_PORT=${SSH_PORT:-8080}
GUEST_USER=${GUEST_USER:-femu}

ssh_opts=(
	-p "$SSH_PORT"
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=10
)
if [[ -r "$SSH_KEY" ]]; then
	ssh_opts+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
fi

exec ssh "${ssh_opts[@]}" "$GUEST_USER@localhost" "$@"
