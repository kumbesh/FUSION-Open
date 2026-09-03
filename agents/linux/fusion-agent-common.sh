#!/usr/bin/env sh
set -eu

FUSION_VECTOR_VERSION=0.58.0
# Used by install.sh when this library is sourced.
# shellcheck disable=SC2034
FUSION_VECTOR_X86_64_SHA256=a4634bea859a7ad7064ff3dd6f6ad7eb0e8dd4493cc41657d84da8dd66f09d09
# shellcheck disable=SC2034
FUSION_VECTOR_AARCH64_SHA256=06d9f9768feb0cb5c7cdfc12e0b737b22f1220967f5455f391a395361b5799e5
FUSION_AGENT_SERVICE=fusion-vector-agent.service
FUSION_AGENT_ROOT=/usr/local/lib/fusion-vector-agent
# shellcheck disable=SC2034
FUSION_AGENT_BINARY=$FUSION_AGENT_ROOT/bin/vector
FUSION_AGENT_CONFIG_DIR=/etc/fusion-vector-agent
# shellcheck disable=SC2034
FUSION_AGENT_CONFIG=$FUSION_AGENT_CONFIG_DIR/vector.yaml
FUSION_AGENT_METADATA=$FUSION_AGENT_CONFIG_DIR/install.env
FUSION_AGENT_DATA=/var/lib/fusion-vector-agent
FUSION_AGENT_LOGS=/var/log/fusion-vector-agent
# shellcheck disable=SC2034
FUSION_AGENT_UNIT=/etc/systemd/system/$FUSION_AGENT_SERVICE
FUSION_AGENT_JOURNALCTL=/usr/bin/journalctl
FUSION_AGENT_SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
FUSION_AGENT_TEMPLATE=$FUSION_AGENT_SCRIPT_DIR/vector.yaml.template
# shellcheck disable=SC2034
FUSION_AGENT_UNIT_SOURCE=$FUSION_AGENT_SCRIPT_DIR/fusion-vector-agent.service

fusion_require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run this command as root (for example, with sudo)." >&2
    exit 1
  fi
}

fusion_require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command '$1' was not found." >&2
    exit 1
  fi
}

fusion_validate_collector_url() {
  url=$1
  if ! printf '%s' "$url" | grep -Eq '^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?/linux$'; then
    echo "Collector URL must be an absolute http(s) URL with the exact /linux path and no credentials, query, or fragment." >&2
    exit 1
  fi
}

fusion_escape_sed() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

fusion_render_config() {
  collector_url=$1
  output_path=$2
  journalctl_path=${3:-$FUSION_AGENT_JOURNALCTL}
  fusion_validate_collector_url "$collector_url"
  if [ ! -f "$FUSION_AGENT_TEMPLATE" ]; then
    echo "Agent template not found at $FUSION_AGENT_TEMPLATE." >&2
    exit 1
  fi

  escaped_url=$(fusion_escape_sed "$collector_url")
  escaped_data=$(fusion_escape_sed "$FUSION_AGENT_DATA")
  escaped_journal_data=$(fusion_escape_sed "$FUSION_AGENT_DATA/journald")
  escaped_logs=$(fusion_escape_sed "$FUSION_AGENT_LOGS")
  escaped_journalctl=$(fusion_escape_sed "$journalctl_path")
  sed \
    -e "s|__FUSION_COLLECTOR_URL__|$escaped_url|g" \
    -e "s|__FUSION_DATA_DIR__|$escaped_data|g" \
    -e "s|__FUSION_JOURNAL_DATA_DIR__|$escaped_journal_data|g" \
    -e "s|__FUSION_LOG_DIR__|$escaped_logs|g" \
    -e "s|__FUSION_JOURNALCTL_PATH__|$escaped_journalctl|g" \
    "$FUSION_AGENT_TEMPLATE" > "$output_path"
}

fusion_assert_auditd_prerequisites() {
  if ! systemctl is-active --quiet auditd.service; then
    echo "auditd is not running. Fusion does not install or configure auditd; satisfy the documented prerequisite and retry." >&2
    exit 1
  fi
  if [ ! -f /var/log/audit/audit.log ]; then
    echo "/var/log/audit/audit.log does not exist. Verify auditd logging before installing the agent." >&2
    exit 1
  fi
  if [ ! -r /var/log/audit/audit.log ]; then
    echo "/var/log/audit/audit.log is not readable by root. Do not weaken its permissions; repair auditd or filesystem policy instead." >&2
    exit 1
  fi
}

fusion_write_metadata() {
  collector_url=$1
  umask 077
  {
    printf 'VECTOR_VERSION=%s\n' "$FUSION_VECTOR_VERSION"
    printf 'COLLECTOR_URL=%s\n' "$collector_url"
    printf 'CONFIGURED_AT_UTC=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } > "$FUSION_AGENT_METADATA"
  chmod 600 "$FUSION_AGENT_METADATA"
}

fusion_read_collector_url() {
  if [ ! -f "$FUSION_AGENT_METADATA" ]; then
    return 1
  fi
  sed -n 's/^COLLECTOR_URL=//p' "$FUSION_AGENT_METADATA" | head -n 1
}
