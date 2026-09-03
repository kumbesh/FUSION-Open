#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=integrations/suricata/fusion-suricata-common.sh
. "$SCRIPT_DIR/fusion-suricata-common.sh"
fusion_suricata_require_root
eve_path=$(fusion_suricata_read_metadata EVE_PATH || printf '/var/log/suricata/eve.json')
fusion_suricata_assert_prerequisites "$eve_path"
systemctl start "$FUSION_SURICATA_SERVICE"
systemctl --no-pager --full status "$FUSION_SURICATA_SERVICE"
