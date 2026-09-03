#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=integrations/suricata/fusion-suricata-common.sh
. "$SCRIPT_DIR/fusion-suricata-common.sh"

purge_data=false
if [ "$#" -gt 1 ]; then echo "Usage: sudo ./uninstall.sh [--purge-data]" >&2; exit 2; fi
if [ "$#" -eq 1 ]; then [ "$1" = "--purge-data" ] || { echo "Usage: sudo ./uninstall.sh [--purge-data]" >&2; exit 2; }; purge_data=true; fi
fusion_suricata_require_root

systemctl disable --now "$FUSION_SURICATA_SERVICE" 2>/dev/null || true
rm -f "$FUSION_SURICATA_UNIT" "$FUSION_SURICATA_CONFIG" "$FUSION_SURICATA_METADATA" "$FUSION_SURICATA_BINARY"
rmdir "$FUSION_SURICATA_ROOT/bin" "$FUSION_SURICATA_ROOT" "$FUSION_SURICATA_CONFIG_DIR" 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed "$FUSION_SURICATA_SERVICE" 2>/dev/null || true
if [ "$purge_data" = true ]; then
  if [ "$FUSION_SURICATA_DATA" != "/var/lib/fusion-suricata-vector" ] || [ "$FUSION_SURICATA_LOGS" != "/var/log/fusion-suricata-vector" ]; then
    echo "Refusing to purge unexpected paths: $FUSION_SURICATA_DATA and $FUSION_SURICATA_LOGS" >&2
    exit 1
  fi
  rm -rf -- "$FUSION_SURICATA_DATA" "$FUSION_SURICATA_LOGS"
  echo "Integration, checkpoints, buffer, and local logs removed. Suricata and EVE JSON were not changed."
else
  echo "Integration removed. Checkpoints, buffer, and logs remain. Suricata was not changed."
fi
