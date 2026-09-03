#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=agents/linux/fusion-agent-common.sh
. "$SCRIPT_DIR/fusion-agent-common.sh"

usage() {
  echo "Usage: sudo ./install.sh <http(s)://fusion-host:8686/linux> [--force] [--no-start]" >&2
}

[ "$#" -ge 1 ] || { usage; exit 2; }
collector_url=$1
shift
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

fusion_require_root
for command_name in systemctl curl tar sha256sum install find sed grep; do
  fusion_require_command "$command_name"
done
fusion_validate_collector_url "$collector_url"
fusion_assert_auditd_prerequisites
if [ ! -x "$FUSION_AGENT_JOURNALCTL" ]; then
  echo "$FUSION_AGENT_JOURNALCTL is unavailable. systemd-journald and journalctl are required." >&2
  exit 1
fi

if systemctl list-unit-files "$FUSION_AGENT_SERVICE" --no-legend 2>/dev/null | grep -q "^$FUSION_AGENT_SERVICE" && [ "$force" != true ]; then
  echo "$FUSION_AGENT_SERVICE is already installed. Use configure.sh, or rerun with --force." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)
    vector_target=x86_64-unknown-linux-gnu
    vector_sha256=$FUSION_VECTOR_X86_64_SHA256
    ;;
  aarch64|arm64)
    vector_target=aarch64-unknown-linux-gnu
    vector_sha256=$FUSION_VECTOR_AARCH64_SHA256
    ;;
  *)
    echo "Unsupported architecture: $(uname -m). Fusion currently supports x86_64 and aarch64 Linux." >&2
    exit 1
    ;;
esac

archive_name="vector-${FUSION_VECTOR_VERSION}-${vector_target}.tar.gz"
download_url="https://github.com/vectordotdev/vector/releases/download/v${FUSION_VECTOR_VERSION}/${archive_name}"
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
archive_path=$temporary_root/$archive_name

echo "Downloading pinned Vector $FUSION_VECTOR_VERSION for $vector_target..."
curl --fail --location --proto '=https' --tlsv1.2 --output "$archive_path" "$download_url"
printf '%s  %s\n' "$vector_sha256" "$archive_path" | sha256sum --check --status || {
  echo "Vector archive checksum verification failed." >&2
  exit 1
}
tar -xzf "$archive_path" -C "$temporary_root"
downloaded_binary=$(find "$temporary_root" -type f -path '*/bin/vector' -print -quit)
if [ -z "$downloaded_binary" ]; then
  echo "The Vector archive did not contain bin/vector." >&2
  exit 1
fi

install -d -m 0755 "$FUSION_AGENT_ROOT/bin"
install -d -m 0750 "$FUSION_AGENT_CONFIG_DIR" "$FUSION_AGENT_DATA" "$FUSION_AGENT_DATA/journald" "$FUSION_AGENT_LOGS"
install -m 0755 "$downloaded_binary" "$FUSION_AGENT_BINARY"

rendered_config=$temporary_root/vector.yaml
fusion_render_config "$collector_url" "$rendered_config"
echo "Validating the Linux Vector configuration..."
"$FUSION_AGENT_BINARY" validate --no-environment --skip-healthchecks --config-yaml "$rendered_config"
install -m 0640 "$rendered_config" "$FUSION_AGENT_CONFIG"
install -m 0644 "$FUSION_AGENT_UNIT_SOURCE" "$FUSION_AGENT_UNIT"
fusion_write_metadata "$collector_url"

systemctl daemon-reload
systemctl enable "$FUSION_AGENT_SERVICE"
if [ "$no_start" = true ]; then
  echo "Fusion Linux Vector agent installed but not started."
else
  systemctl restart "$FUSION_AGENT_SERVICE"
  echo "Fusion Linux Vector agent installed and started."
fi
echo "Collector: $collector_url"
echo "Configuration: $FUSION_AGENT_CONFIG"
case "$collector_url" in
  http://*) echo "WARNING: This endpoint has no TLS or authentication. Use it only on an isolated, firewall-restricted lab network." >&2 ;;
esac
