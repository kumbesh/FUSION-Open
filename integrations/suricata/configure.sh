#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=integrations/suricata/fusion-suricata-common.sh
. "$SCRIPT_DIR/fusion-suricata-common.sh"

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "Usage: sudo ./configure.sh <http(s)://fusion-host:8686/security> [eve-path] [sensor-name]" >&2
  exit 2
fi
collector_url=$1
eve_path=${2:-$(fusion_suricata_read_metadata EVE_PATH || printf '/var/log/suricata/eve.json')}
sensor_name=${3:-$(fusion_suricata_read_metadata SENSOR_NAME || hostname)}
fusion_suricata_require_root
fusion_suricata_assert_prerequisites "$eve_path"
if [ ! -x "$FUSION_SURICATA_BINARY" ] || [ ! -f "$FUSION_SURICATA_UNIT" ]; then
  echo "Fusion Suricata integration is not installed. Run install.sh first." >&2
  exit 1
fi

temporary_config=$(mktemp)
trap 'rm -f "$temporary_config"' EXIT HUP INT TERM
fusion_suricata_render_config "$collector_url" "$eve_path" "$temporary_config" "$sensor_name"
"$FUSION_SURICATA_BINARY" validate --no-environment --skip-healthchecks --config-yaml "$temporary_config"
install -m 0640 -o root -g root "$temporary_config" "$FUSION_SURICATA_CONFIG"
fusion_suricata_write_metadata "$collector_url" "$eve_path" "$sensor_name"
if systemctl is-active --quiet "$FUSION_SURICATA_SERVICE"; then
  systemctl restart "$FUSION_SURICATA_SERVICE"
  echo "Configuration updated and $FUSION_SURICATA_SERVICE restarted."
else
  echo "Configuration updated. Start the integration with ./start.sh."
fi
case "$collector_url" in http://*) echo "WARNING: HTTP 8686 has no TLS or authentication. Keep it on an isolated lab network." >&2 ;; esac
