#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=integrations/suricata/fusion-suricata-common.sh
. "$SCRIPT_DIR/fusion-suricata-common.sh"

eve_path=$(fusion_suricata_read_metadata EVE_PATH || printf '/var/log/suricata/eve.json')
echo "Fusion Suricata integration prerequisites"
if systemctl is-active --quiet suricata.service; then echo "  Suricata service: active"; else echo "  Suricata service: not active or differently named"; fi
if [ -r "$eve_path" ]; then echo "  EVE JSON: readable ($eve_path)"; else echo "  EVE JSON: NOT readable ($eve_path)"; fi
if collector_url=$(fusion_suricata_read_metadata COLLECTOR_URL); then echo "  collector: $collector_url"; fi
echo
systemctl --no-pager --full status "$FUSION_SURICATA_SERVICE" || true
echo
echo "Recent integration logs"
journalctl --no-pager --unit "$FUSION_SURICATA_SERVICE" --lines 20 || true
