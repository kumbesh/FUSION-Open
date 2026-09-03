#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=integrations/suricata/fusion-suricata-common.sh
. "$SCRIPT_DIR/fusion-suricata-common.sh"

vector_binary=${1:-vector}
if ! command -v "$vector_binary" >/dev/null 2>&1 && [ ! -x "$vector_binary" ]; then
  echo "Usage: ./test-config.sh [path-to-vector-0.58.0]" >&2
  exit 2
fi
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
eve_path=$temporary_root/eve.json
rendered_config=$temporary_root/vector.yaml
: > "$eve_path"
fusion_suricata_render_config "http://192.0.2.10:8686/security" "$eve_path" "$rendered_config" "suricata-test-sensor"
grep -q 'destination_ip == "192.0.2.10" && destination_port == 8686' "$rendered_config" || {
  echo "Rendered configuration is missing the collector feedback-loop exclusion." >&2
  exit 1
}
"$vector_binary" validate --no-environment --skip-healthchecks --config-yaml "$rendered_config"
"$vector_binary" test --config-yaml "$rendered_config"
echo "Suricata EVE Vector integration configuration is valid."
