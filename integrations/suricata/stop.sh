#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=integrations/suricata/fusion-suricata-common.sh
. "$SCRIPT_DIR/fusion-suricata-common.sh"
fusion_suricata_require_root
systemctl stop "$FUSION_SURICATA_SERVICE"
echo "$FUSION_SURICATA_SERVICE stopped. Suricata was not changed."
