#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=integrations/suricata/fusion-suricata-common.sh
. "$SCRIPT_DIR/fusion-suricata-common.sh"

usage() {
  echo "Usage: sudo ./install.sh <http(s)://fusion-host:8686/security> [eve-path] [sensor-name] [--force] [--no-start]" >&2
}

[ "$#" -ge 1 ] || { usage; exit 2; }
collector_url=$1
shift
eve_path=/var/log/suricata/eve.json
sensor_name=$(hostname)
if [ "$#" -gt 0 ] && [ "${1#--}" = "$1" ]; then eve_path=$1; shift; fi
if [ "$#" -gt 0 ] && [ "${1#--}" = "$1" ]; then sensor_name=$1; shift; fi
force=false
no_start=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --force) force=true ;;
    --no-start) no_start=true ;;
    *) usage; exit 2 ;;
  esac
  shift
done

fusion_suricata_require_root
for command_name in systemctl curl tar sha256sum install find sed grep hostname; do
  fusion_suricata_require_command "$command_name"
done
fusion_suricata_validate_collector_url "$collector_url"
fusion_suricata_assert_prerequisites "$eve_path"

if systemctl list-unit-files "$FUSION_SURICATA_SERVICE" --no-legend 2>/dev/null | grep -q "^$FUSION_SURICATA_SERVICE" && [ "$force" != true ]; then
  echo "$FUSION_SURICATA_SERVICE is already installed. Use configure.sh, or rerun with --force." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) vector_target=x86_64-unknown-linux-gnu; vector_sha256=$FUSION_SURICATA_VECTOR_X86_64_SHA256 ;;
  aarch64|arm64) vector_target=aarch64-unknown-linux-gnu; vector_sha256=$FUSION_SURICATA_VECTOR_AARCH64_SHA256 ;;
  *) echo "Unsupported architecture: $(uname -m). Fusion supports x86_64 and aarch64 Linux." >&2; exit 1 ;;
esac

archive_name="vector-${FUSION_SURICATA_VECTOR_VERSION}-${vector_target}.tar.gz"
download_url="https://github.com/vectordotdev/vector/releases/download/v${FUSION_SURICATA_VECTOR_VERSION}/${archive_name}"
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
archive_path=$temporary_root/$archive_name

echo "Downloading pinned Vector $FUSION_SURICATA_VECTOR_VERSION for $vector_target..."
curl --fail --location --proto '=https' --tlsv1.2 --output "$archive_path" "$download_url"
printf '%s  %s\n' "$vector_sha256" "$archive_path" | sha256sum --check --status || { echo "Vector archive checksum verification failed." >&2; exit 1; }
tar -xzf "$archive_path" -C "$temporary_root"
downloaded_binary=$(find "$temporary_root" -type f -path '*/bin/vector' -print -quit)
[ -n "$downloaded_binary" ] || { echo "The Vector archive did not contain bin/vector." >&2; exit 1; }

install -d -m 0755 "$FUSION_SURICATA_ROOT/bin"
install -d -m 0750 "$FUSION_SURICATA_CONFIG_DIR" "$FUSION_SURICATA_DATA" "$FUSION_SURICATA_LOGS"
install -m 0755 "$downloaded_binary" "$FUSION_SURICATA_BINARY"
rendered_config=$temporary_root/vector.yaml
fusion_suricata_render_config "$collector_url" "$eve_path" "$rendered_config" "$sensor_name"
"$FUSION_SURICATA_BINARY" validate --no-environment --skip-healthchecks --config-yaml "$rendered_config"
install -m 0640 "$rendered_config" "$FUSION_SURICATA_CONFIG"
install -m 0644 "$FUSION_SURICATA_UNIT_SOURCE" "$FUSION_SURICATA_UNIT"
fusion_suricata_write_metadata "$collector_url" "$eve_path" "$sensor_name"

systemctl daemon-reload
systemctl enable "$FUSION_SURICATA_SERVICE"
if [ "$no_start" = true ]; then
  echo "Fusion Suricata integration installed but not started."
else
  systemctl restart "$FUSION_SURICATA_SERVICE"
  echo "Fusion Suricata integration installed and started."
fi
echo "EVE source: $eve_path"
echo "Collector: $collector_url"
case "$collector_url" in http://*) echo "WARNING: HTTP 8686 has no TLS or authentication. Use only an isolated, firewall-restricted lab network." >&2 ;; esac
