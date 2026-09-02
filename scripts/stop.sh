#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

fusion_assert_engine
echo "Stopping Fusion without deleting data..."
fusion_compose down --remove-orphans
echo "Fusion stopped. Docker volumes were preserved."

