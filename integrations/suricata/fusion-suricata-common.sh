#!/usr/bin/env sh
set -eu

FUSION_SURICATA_VECTOR_VERSION=0.58.0
# shellcheck disable=SC2034
FUSION_SURICATA_VECTOR_X86_64_SHA256=a4634bea859a7ad7064ff3dd6f6ad7eb0e8dd4493cc41657d84da8dd66f09d09
# shellcheck disable=SC2034
FUSION_SURICATA_VECTOR_AARCH64_SHA256=06d9f9768feb0cb5c7cdfc12e0b737b22f1220967f5455f391a395361b5799e5
FUSION_SURICATA_SERVICE=fusion-suricata-vector.service
FUSION_SURICATA_ROOT=/usr/local/lib/fusion-suricata-vector
# shellcheck disable=SC2034
FUSION_SURICATA_BINARY=$FUSION_SURICATA_ROOT/bin/vector
FUSION_SURICATA_CONFIG_DIR=/etc/fusion-suricata-vector
# shellcheck disable=SC2034
FUSION_SURICATA_CONFIG=$FUSION_SURICATA_CONFIG_DIR/vector.yaml
FUSION_SURICATA_METADATA=$FUSION_SURICATA_CONFIG_DIR/install.env
FUSION_SURICATA_DATA=/var/lib/fusion-suricata-vector
FUSION_SURICATA_LOGS=/var/log/fusion-suricata-vector
# shellcheck disable=SC2034
FUSION_SURICATA_UNIT=/etc/systemd/system/$FUSION_SURICATA_SERVICE
FUSION_SURICATA_SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
FUSION_SURICATA_TEMPLATE=$FUSION_SURICATA_SCRIPT_DIR/vector.yaml.template
# shellcheck disable=SC2034
FUSION_SURICATA_UNIT_SOURCE=$FUSION_SURICATA_SCRIPT_DIR/fusion-suricata-vector.service

fusion_suricata_require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run this command as root (for example, with sudo)." >&2
    exit 1
  fi
}

fusion_suricata_require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command '$1' was not found." >&2
    exit 1
  fi
}

fusion_suricata_validate_collector_url() {
  collector_url=$1
  if ! printf '%s' "$collector_url" | grep -Eq '^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?/security$'; then
    echo "Collector URL must be an absolute http(s) URL with the exact /security path and no credentials, query, or fragment." >&2
    exit 1
  fi
}

fusion_suricata_validate_eve_path() {
  eve_path=$1
  case "$eve_path" in
    /*) ;;
    *) echo "EVE path must be absolute." >&2; exit 1 ;;
  esac
  if printf '%s' "$eve_path" | grep -q '[[:cntrl:]]'; then
    echo "EVE path contains invalid control characters." >&2
    exit 1
  fi
  case "$eve_path" in
    *"'"*) echo "EVE path cannot contain a single quote." >&2; exit 1 ;;
  esac
}

fusion_suricata_validate_sensor_name() {
  sensor_name=$1
  if ! printf '%s' "$sensor_name" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'; then
    echo "Sensor name must be 1-128 characters using only letters, numbers, dot, underscore, and hyphen." >&2
    exit 1
  fi
}

fusion_suricata_escape_sed() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

fusion_suricata_render_config() {
  collector_url=$1
  eve_path=$2
  output_path=$3
  sensor_name=${4:-fusion-suricata-sensor}
  fusion_suricata_validate_collector_url "$collector_url"
  fusion_suricata_validate_eve_path "$eve_path"
  fusion_suricata_validate_sensor_name "$sensor_name"
  [ -f "$FUSION_SURICATA_TEMPLATE" ] || { echo "Integration template not found at $FUSION_SURICATA_TEMPLATE." >&2; exit 1; }

  collector_scheme=${collector_url%%://*}
  collector_target=${collector_url#*://}
  collector_authority=${collector_target%%/*}
  case "$collector_authority" in
    \[*\]*)
      collector_ip=${collector_authority#\[}
      collector_ip=${collector_ip%%\]*}
      collector_port_part=${collector_authority#*\]}
      case "$collector_port_part" in
        :*) collector_port=${collector_port_part#:} ;;
        "") if [ "$collector_scheme" = "https" ]; then collector_port=443; else collector_port=80; fi ;;
        *) echo "Invalid bracketed collector address." >&2; exit 1 ;;
      esac
      ;;
    *:*)
      collector_ip=${collector_authority%:*}
      collector_port=${collector_authority##*:}
      ;;
    *)
      collector_ip=$collector_authority
      if [ "$collector_scheme" = "https" ]; then collector_port=443; else collector_port=80; fi
      ;;
  esac
  case "$collector_ip" in
    *:*) ;;
    *)
      if ! printf '%s' "$collector_ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        echo "The Suricata collector URL must use a literal Fusion host IP so the shipper can exclude its own monitored traffic." >&2
        exit 1
      fi
      ;;
  esac

  escaped_url=$(fusion_suricata_escape_sed "$collector_url")
  escaped_collector_ip=$(fusion_suricata_escape_sed "$collector_ip")
  escaped_eve=$(fusion_suricata_escape_sed "$eve_path")
  escaped_sensor=$(fusion_suricata_escape_sed "$sensor_name")
  escaped_data=$(fusion_suricata_escape_sed "$FUSION_SURICATA_DATA")
  escaped_logs=$(fusion_suricata_escape_sed "$FUSION_SURICATA_LOGS")
  sed \
    -e "s|__FUSION_COLLECTOR_URL__|$escaped_url|g" \
    -e "s|__FUSION_COLLECTOR_IP__|$escaped_collector_ip|g" \
    -e "s|__FUSION_COLLECTOR_PORT__|$collector_port|g" \
    -e "s|__SURICATA_EVE_PATH__|$escaped_eve|g" \
    -e "s|__SURICATA_SENSOR_NAME__|$escaped_sensor|g" \
    -e "s|__FUSION_DATA_DIR__|$escaped_data|g" \
    -e "s|__FUSION_LOG_DIR__|$escaped_logs|g" \
    "$FUSION_SURICATA_TEMPLATE" > "$output_path"
}

fusion_suricata_assert_prerequisites() {
  eve_path=$1
  fusion_suricata_validate_eve_path "$eve_path"
  if [ ! -f "$eve_path" ]; then
    echo "$eve_path does not exist. Fusion does not install or configure Suricata; enable EVE JSON first." >&2
    exit 1
  fi
  if [ ! -r "$eve_path" ]; then
    echo "$eve_path is not readable by root. Repair the Suricata or filesystem configuration without weakening access globally." >&2
    exit 1
  fi
}

fusion_suricata_write_metadata() {
  collector_url=$1
  eve_path=$2
  sensor_name=$3
  umask 077
  {
    printf 'VECTOR_VERSION=%s\n' "$FUSION_SURICATA_VECTOR_VERSION"
    printf 'COLLECTOR_URL=%s\n' "$collector_url"
    printf 'EVE_PATH=%s\n' "$eve_path"
    printf 'SENSOR_NAME=%s\n' "$sensor_name"
    printf 'CONFIGURED_AT_UTC=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } > "$FUSION_SURICATA_METADATA"
  chmod 600 "$FUSION_SURICATA_METADATA"
}

fusion_suricata_read_metadata() {
  key=$1
  [ -f "$FUSION_SURICATA_METADATA" ] || return 1
  sed -n "s/^${key}=//p" "$FUSION_SURICATA_METADATA" | head -n 1
}
