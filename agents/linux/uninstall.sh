#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=agents/linux/fusion-agent-common.sh
. "$SCRIPT_DIR/fusion-agent-common.sh"

purge_data=false
if [ "$#" -gt 1 ]; then
  echo "Usage: sudo ./uninstall.sh [--purge-data]" >&2
  exit 2
fi
if [ "$#" -eq 1 ]; then
  [ "$1" = "--purge-data" ] || { echo "Usage: sudo ./uninstall.sh [--purge-data]" >&2; exit 2; }
  purge_data=true
fi
fusion_require_root

systemctl disable --now "$FUSION_AGENT_SERVICE" 2>/dev/null || true
rm -f "$FUSION_AGENT_UNIT"
rm -f "$FUSION_AGENT_CONFIG" "$FUSION_AGENT_METADATA"
rm -f "$FUSION_AGENT_BINARY"
rmdir "$FUSION_AGENT_ROOT/bin" "$FUSION_AGENT_ROOT" "$FUSION_AGENT_CONFIG_DIR" 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed "$FUSION_AGENT_SERVICE" 2>/dev/null || true

if [ "$purge_data" = true ]; then
  if [ "$FUSION_AGENT_DATA" != "/var/lib/fusion-vector-agent" ] || [ "$FUSION_AGENT_LOGS" != "/var/log/fusion-vector-agent" ]; then
    echo "Refusing to purge unexpected paths: $FUSION_AGENT_DATA and $FUSION_AGENT_LOGS" >&2
    exit 1
  fi
  rm -rf -- "$FUSION_AGENT_DATA" "$FUSION_AGENT_LOGS"
  echo "Agent, checkpoints, buffer, and local Vector logs removed. auditd and journald were not changed."
else
  echo "Agent removed. Checkpoints, buffer, and logs remain in $FUSION_AGENT_DATA and $FUSION_AGENT_LOGS."
fi
