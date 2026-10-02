#!/usr/bin/env bash
# Cron de backup: dispara alerta se o import já terminou e o watcher falhou.
set -euo pipefail
PROJECT_DIR="${IMPORT_PROJECT_DIR:-/opt/anti-retest}"
exec "$PROJECT_DIR/scripts/import-send-alert.sh"
