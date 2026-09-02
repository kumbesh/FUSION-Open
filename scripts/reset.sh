#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

force=false
skip_pull=false
for arg in "$@"; do
  case "$arg" in
    --force) force=true ;;
    --skip-pull) skip_pull=true ;;
    *) echo "Usage: $0 [--force] [--skip-pull]" >&2; exit 2 ;;
  esac
done

fusion_assert_engine
if [ "$force" = false ]; then
  printf "Reset permanently deletes all Fusion ClickHouse, Grafana, and Vector data. Continue? [y/N] "
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Reset cancelled."; exit 0 ;;
  esac
fi

echo "Removing Fusion containers and data volumes..."
fusion_compose down --volumes --remove-orphans
if [ "$skip_pull" = true ]; then
  "$SCRIPT_DIR/deploy.sh" --skip-pull
else
  "$SCRIPT_DIR/deploy.sh"
fi

