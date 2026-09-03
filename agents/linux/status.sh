#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=agents/linux/fusion-agent-common.sh
. "$SCRIPT_DIR/fusion-agent-common.sh"

echo "Fusion Linux endpoint prerequisites"
if systemctl is-active --quiet auditd.service; then
  echo "  auditd: active"
else
  echo "  auditd: NOT active"
fi
if [ -r /var/log/audit/audit.log ]; then
  echo "  audit log: readable"
else
  echo "  audit log: NOT readable"
fi
if [ -x "$FUSION_AGENT_JOURNALCTL" ]; then
  echo "  journalctl: available"
else
  echo "  journalctl: NOT available"
fi
if collector_url=$(fusion_read_collector_url); then
  echo "  collector: $collector_url"
fi
echo
systemctl --no-pager --full status "$FUSION_AGENT_SERVICE" || true
echo
echo "Recent agent logs"
journalctl --no-pager --unit "$FUSION_AGENT_SERVICE" --lines 20 || true
