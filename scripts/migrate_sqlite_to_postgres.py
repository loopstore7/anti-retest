#!/usr/bin/env python3
"""Migra antiretest.db (SQLite) para PostgreSQL sem perder registros."""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

import psycopg

from antiretest.engine_pg import PG_SCHEMA

BATCH = int(os.environ.get("MIGRATE_BATCH", "5000"))


def parse_ts(raw: str) -> datetime:
    dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def main() -> int:
    sqlite_path = os.environ.get("SQLITE_PATH", "backups/antiretest-latest.db")
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL obrigatório", file=sys.stderr)
        return 2
    if not os.path.isfile(sqlite_path):
        print(f"SQLite não encontrado: {sqlite_path}", file=sys.stderr)
        return 2

    src = sqlite3.connect(sqlite_path)
    src.row_factory = sqlite3.Row

    with psycopg.connect(dsn) as dst:
        dst.execute(PG_SCHEMA)
        dst.commit()

        meta_rows = src.execute("SELECT key, value FROM meta").fetchall()
        for row in meta_rows:
            dst.execute(
                "INSERT INTO meta (key, value) VALUES (%s, %s)"
                " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                (row["key"], row["value"]),
            )
        # O SQLite chaveia só pelo número; a API fica travada até rodar migrate_fp_cartao.py.
        dst.execute("DELETE FROM meta WHERE key = 'fp_scheme'")
        dst.commit()
        print(f"meta: {len(meta_rows)} chave(s) migrada(s)")

        total = src.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        print(f"migrando {total:,} registros (lote {BATCH})...".replace(",", "."))

        cur = src.execute("SELECT * FROM entries ORDER BY fingerprint")
        migrated = 0
        t0 = time.time()
        batch: list[tuple] = []

        insert_sql = (
            "INSERT INTO entries"
            " (fingerprint, bin, last4, added_at, added_on, last_seen_at,"
            " attempts, pan_length, vulgo, cc_full)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (fingerprint) DO UPDATE SET"
            " cc_full = CASE WHEN EXCLUDED.cc_full != '' THEN EXCLUDED.cc_full ELSE entries.cc_full END,"
            " attempts = GREATEST(entries.attempts, EXCLUDED.attempts),"
            " last_seen_at = GREATEST(entries.last_seen_at, EXCLUDED.last_seen_at)"
        )

        while True:
            row = cur.fetchone()
            if row is None:
                if batch:
                    with dst.cursor() as c:
                        c.executemany(insert_sql, batch)
                    dst.commit()
                    migrated += len(batch)
                break
            batch.append((
                row["fingerprint"],
                row["bin"],
                row["last4"],
                parse_ts(row["added_at"]),
                row["added_on"],
                parse_ts(row["last_seen_at"]),
                int(row["attempts"]),
                int(row["pan_length"] or 16),
                row["vulgo"] or "",
                row["cc_full"] or "",
            ))
            if len(batch) >= BATCH:
                with dst.cursor() as c:
                    c.executemany(insert_sql, batch)
                dst.commit()
                migrated += len(batch)
                batch = []
                if migrated % 100_000 == 0 or migrated == total:
                    elapsed = max(time.time() - t0, 0.001)
                    rate = migrated / elapsed
                    print(f"  {migrated:,}/{total:,} ({rate:,.0f}/s)".replace(",", "."))

        pg_total = dst.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        pg_cc = dst.execute("SELECT COUNT(*) FROM entries WHERE cc_full != ''").fetchone()[0]
        print(f"concluído: sqlite={total:,} postgres={pg_total:,} cc_full={pg_cc:,}".replace(",", "."))
        if pg_total < total:
            print("AVISO: contagem PostgreSQL menor que SQLite — verifique logs", file=sys.stderr)
            return 1
    src.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
