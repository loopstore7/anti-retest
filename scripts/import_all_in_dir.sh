#!/usr/bin/env bash
# Importa todos os arquivos regulares de um diretório (txt, bac, etc.) via import_txt_to_postgres_fast.py
set -euo pipefail
DIR="${1:-/antrt}"
PY="${2:-/app/scripts/import_txt_to_postgres_fast.py}"
mapfile -t FILES < <(find "$DIR" -maxdepth 1 -type f ! -name '.*' | sort)
if ((${#FILES[@]} == 0)); then
  echo "Nenhum arquivo em $DIR" >&2
  exit 2
fi
echo "Importando ${#FILES[@]} arquivo(s) de $DIR…" >&2
for f in "${FILES[@]}"; do
  echo "  - $f" >&2
done
exec python "$PY" "${FILES[@]}"
