#!/usr/bin/env python3
"""Importa arquivo(s) texto para PostgreSQL (esquema cartao + HMAC em meta.key)."""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from antiretest.core import InvalidNumberError, format_cc_full_from_entry, parse_entry
from antiretest.engine_pg import PG_SCHEMA, card_fingerprint

BATCH = int(os.environ.get("IMPORT_BATCH", os.environ.get("MIGRATE_BATCH", "5000")))


def resolve_key(conn: psycopg.Connection) -> bytes:
    from_env = os.environ.get("ANTIRETEST_KEY")
    if from_env:
        return from_env.encode("utf-8")
    row = conn.execute("SELECT value FROM meta WHERE key = 'key'").fetchone()
    if not row:
        raise SystemExit("Chave HMAC não encontrada (meta.key ou ANTIRETEST_KEY).")
    return bytes.fromhex(row[0])


def flush_batch(
    conn: psycopg.Connection,
    rows: list[tuple],
) -> tuple[int, int]:
    """Insere lote deduplicado; retorna (inseridos, já existiam no banco)."""
    if not rows:
        return 0, 0
    unique: dict[str, tuple] = {}
    for row in rows:
        unique.setdefault(row[0], row)
    dup_no_arquivo = len(rows) - len(unique)
    payload = list(unique.values())
    insert_sql = (
        "INSERT INTO entries"
        " (fingerprint, bin, last4, added_at, added_on, last_seen_at,"
        " attempts, pan_length, vulgo, cc_full)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        " ON CONFLICT (fingerprint) DO NOTHING"
    )
    with conn.cursor() as cur:
        cur.executemany(insert_sql, payload)
        inserted = max(int(cur.rowcount), 0)
    conn.commit()
    skipped_db = len(payload) - inserted
    return inserted, dup_no_arquivo + skipped_db


def import_one_file(conn: psycopg.Connection, key: bytes, path: Path) -> dict[str, int]:
    moment = datetime.now(timezone.utc)
    stats = {"lines": 0, "imported": 0, "duplicates": 0, "invalid": 0, "empty": 0, "expired": 0}
    batch: list[tuple] = []
    t0 = time.time()
    print(f"importando {path} (lote {BATCH})...", flush=True)

    with path.open(encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            stats["lines"] += 1
            stripped = line.strip()
            if not stripped:
                stats["empty"] += 1
                continue
            try:
                entry = parse_entry(stripped)
            except InvalidNumberError:
                stats["invalid"] += 1
                continue

            digits = entry.pan
            if entry.is_expired(moment.astimezone().date()):
                stats["expired"] += 1

            cc_full = format_cc_full_from_entry(entry)
            fp = card_fingerprint(cc_full, key)
            batch.append(
                (
                    fp,
                    digits[:6],
                    digits[-4:],
                    moment,
                    moment.date(),
                    moment,
                    1,
                    len(digits),
                    "",
                    cc_full,
                )
            )
            if len(batch) >= BATCH:
                ins, dup = flush_batch(conn, batch)
                stats["imported"] += ins
                stats["duplicates"] += dup
                batch = []
                if stats["lines"] % 500_000 == 0:
                    elapsed = max(time.time() - t0, 0.001)
                    rate = stats["lines"] / elapsed
                    print(
                        f"  {path.name}: {stats['lines']:,} linhas · "
                        f"{stats['imported']:,} novo(s) · {stats['duplicates']:,} dup · "
                        f"{rate:,.0f} lin/s".replace(",", "."),
                        flush=True,
                    )

    if batch:
        ins, dup = flush_batch(conn, batch)
        stats["imported"] += ins
        stats["duplicates"] += dup

    elapsed = max(time.time() - t0, 0.001)
    print(
        f"concluído {path.name}: {stats['imported']:,} importado(s) · "
        f"{stats['duplicates']:,} duplicado(s) · {stats['invalid']:,} inválido(s) · "
        f"{stats['expired']:,} vencido(s) · {stats['lines']:,} linha(s) · "
        f"{elapsed:.0f}s".replace(",", "."),
        flush=True,
    )
    return stats


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        raw = os.environ.get("IMPORT_PATHS", "").strip()
        if raw:
            paths = [Path(p.strip()) for p in raw.split(",") if p.strip()]
    if not paths:
        print("Uso: import_txt_to_postgres.py arquivo.txt [arquivo2.txt ...]", file=sys.stderr)
        return 2

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL obrigatório", file=sys.stderr)
        return 2

    for path in paths:
        if not path.is_file():
            print(f"arquivo não encontrado: {path}", file=sys.stderr)
            return 2

    totals = {"lines": 0, "imported": 0, "duplicates": 0, "invalid": 0, "empty": 0, "expired": 0}
    with psycopg.connect(dsn) as conn:
        conn.execute(PG_SCHEMA)
        conn.commit()
        scheme = conn.execute("SELECT value FROM meta WHERE key = 'fp_scheme'").fetchone()
        if not scheme or scheme[0] != "cartao":
            print(
                "AVISO: fp_scheme não é 'cartao' — import use card_fingerprint; "
                "rode migrate-fp se a base for antiga.",
                file=sys.stderr,
            )
        key = resolve_key(conn)
        for path in paths:
            st = import_one_file(conn, key, path)
            for k in totals:
                totals[k] += st[k]

        pg_total = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        print(f"postgres entries: {pg_total:,}".replace(",", "."))

    print(
        f"TOTAL: {totals['imported']:,} importado(s) · {totals['duplicates']:,} duplicado(s) · "
        f"{totals['invalid']:,} inválido(s) · {totals['lines']:,} linha(s)".replace(",", ".")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
