#!/usr/bin/env bash
# Aguarda o container de import parar e dispara alerta uma vez.
set -euo pipefail

CONTAINER="${IMPORT_CONTAINER_NAME:-anti-retest-import}"
INTERVAL="${IMPORT_WATCH_INTERVAL_SEC:-60}"
PROJECT_DIR="${IMPORT_PROJECT_DIR:-/opt/anti-retest}"
LOG="$PROJECT_DIR/import-watch.log"

echo "$(date -Iseconds) watcher iniciado (container=$CONTAINER interval=${INTERVAL}s)" >>"$LOG"

while true; do
  if docker inspect "$CONTAINER" &>/dev/null; then
    status="$(docker inspect -f '{{.State.Status}}' "$CONTAINER")"
    if [[ "$status" != "running" ]]; then
      "$PROJECT_DIR/scripts/import-send-alert.sh"
      echo "$(date -Iseconds) watcher encerrado após alerta" >>"$LOG"
      exit 0
    fi
  fi
  sleep "$INTERVAL"
done
