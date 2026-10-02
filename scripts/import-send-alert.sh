#!/usr/bin/env bash
# Envia alerta único quando o import PostgreSQL termina (chamado pelos watchers).
set -euo pipefail

CONTAINER="${IMPORT_CONTAINER_NAME:-anti-retest-import}"
PROJECT_DIR="${IMPORT_PROJECT_DIR:-/opt/anti-retest}"
REPORT="$PROJECT_DIR/import-finished.report"
ALERT_SENT="$PROJECT_DIR/.import-alert-sent"
NOTIFY_ENV="$PROJECT_DIR/.import-notify.env"

if [[ -f "$ALERT_SENT" ]]; then
  exit 0
fi

if ! docker inspect "$CONTAINER" &>/dev/null; then
  exit 0
fi

status="$(docker inspect -f '{{.State.Status}}' "$CONTAINER")"
if [[ "$status" == "running" ]]; then
  exit 0
fi

exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$CONTAINER")"
started="$(docker inspect -f '{{.State.StartedAt}}' "$CONTAINER")"
finished="$(docker inspect -f '{{.State.FinishedAt}}' "$CONTAINER")"

pg_count=""
if docker inspect anti-retest-postgres &>/dev/null; then
  pg_count="$(docker exec anti-retest-postgres psql -U antiretest -d antiretest -t -A -c "SELECT COUNT(*) FROM entries;" 2>/dev/null || true)"
fi

logs_tail="$(docker logs "$CONTAINER" 2>&1 | tail -n 40 || true)"

{
  echo "Anti-retest import — $(date -Iseconds)"
  echo "Container: $CONTAINER"
  echo "Status: $status"
  echo "Exit code: $exit_code"
  echo "Início: $started"
  echo "Fim: $finished"
  echo "Entries no Postgres: ${pg_count:-n/d}"
  echo ""
  echo "=== Últimas linhas do log ==="
  echo "$logs_tail"
} >"$REPORT"

touch "$ALERT_SENT"

msg="[anti-retest] Import finalizado: exit=$exit_code entries=${pg_count:-?} — ver $REPORT"
logger -t anti-retest-import "$msg"
echo "$(date -Iseconds) $msg" >>"$PROJECT_DIR/import-watch.log"

if [[ -f "$NOTIFY_ENV" ]]; then
  # shellcheck disable=SC1090
  set -a
  source "$NOTIFY_ENV"
  set +a
fi

if [[ -n "${IMPORT_NOTIFY_WEBHOOK_URL:-}" ]]; then
  json_body="$(MSG="$msg" python3 -c 'import json,os; print(json.dumps({"text": os.environ["MSG"], "content": os.environ["MSG"]}))')"
  curl -fsS -m 30 -X POST "$IMPORT_NOTIFY_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "$json_body" \
    >/dev/null 2>&1 || true
fi

if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
  curl -fsS -m 30 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=$msg" \
    >/dev/null 2>&1 || true
fi

exit 0
