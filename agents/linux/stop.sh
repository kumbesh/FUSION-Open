#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=agents/linux/fusion-agent-common.sh
. "$SCRIPT_DIR/fusion-agent-common.sh"
fusion_require_root
systemctl stop "$FUSION_AGENT_SERVICE"
echo "$FUSION_AGENT_SERVICE stopped. auditd and systemd-journald were not changed."
