#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=agents/linux/fusion-agent-common.sh
. "$SCRIPT_DIR/fusion-agent-common.sh"
fusion_require_root
fusion_assert_auditd_prerequisites
systemctl start "$FUSION_AGENT_SERVICE"
systemctl --no-pager --full status "$FUSION_AGENT_SERVICE"
