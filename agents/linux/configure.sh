#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=agents/linux/fusion-agent-common.sh
. "$SCRIPT_DIR/fusion-agent-common.sh"

if [ "$#" -ne 1 ]; then
  echo "Usage: sudo ./configure.sh <http(s)://fusion-host:8686/linux>" >&2
  exit 2
fi
collector_url=$1
fusion_require_root
fusion_validate_collector_url "$collector_url"

if [ ! -x "$FUSION_AGENT_BINARY" ] || [ ! -f "$FUSION_AGENT_UNIT" ]; then
  echo "Fusion Linux Vector agent is not installed. Run install.sh first." >&2
  exit 1
fi
temporary_config=$(mktemp)
trap 'rm -f "$temporary_config"' EXIT HUP INT TERM
fusion_render_config "$collector_url" "$temporary_config"
"$FUSION_AGENT_BINARY" validate --no-environment --skip-healthchecks --config-yaml "$temporary_config"
install -m 0640 -o root -g root "$temporary_config" "$FUSION_AGENT_CONFIG"
fusion_write_metadata "$collector_url"

if systemctl is-active --quiet "$FUSION_AGENT_SERVICE"; then
  systemctl restart "$FUSION_AGENT_SERVICE"
  echo "Configuration updated and $FUSION_AGENT_SERVICE restarted."
else
  echo "Configuration updated. Start the agent with ./start.sh."
fi
case "$collector_url" in
  http://*) echo "WARNING: This endpoint has no TLS or authentication. Keep it on an isolated, firewall-restricted lab network." >&2 ;;
esac
