#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=agents/linux/fusion-agent-common.sh
. "$SCRIPT_DIR/fusion-agent-common.sh"

vector_binary=${1:-vector}
if ! command -v "$vector_binary" >/dev/null 2>&1 && [ ! -x "$vector_binary" ]; then
  echo "Usage: ./test-config.sh [path-to-vector-0.58.0]" >&2
  exit 2
fi

temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
fake_journalctl=$temporary_root/journalctl
audit_log=$temporary_root/audit.log
rendered_config=$temporary_root/vector.yaml
printf '%s\n' '#!/usr/bin/env sh' 'echo "systemd 255 (255.4-1)"' > "$fake_journalctl"
chmod 0755 "$fake_journalctl"
: > "$audit_log"

fusion_render_config "http://192.0.2.10:8686/linux" "$rendered_config" "$fake_journalctl"
escaped_audit=$(fusion_escape_sed "$audit_log")
sed "s|/var/log/audit/audit.log|$escaped_audit|g" "$rendered_config" > "$temporary_root/vector.test.yaml"
"$vector_binary" validate --no-environment --skip-healthchecks --config-yaml "$temporary_root/vector.test.yaml"
echo "Linux Vector agent configuration is valid."
