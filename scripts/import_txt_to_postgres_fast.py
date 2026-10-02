#!/usr/bin/env python3
"""Importação em massa: regex rápida, workers paralelos, COPY + staging, sync commit off."""

from __future__ import annotations

import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

import psycopg

from antiretest.core import (
    InvalidNumberError,
    format_cc_full,
    looks_like_pan,
    parse_entry,
)
from antiretest.engine_pg import PG_SCHEMA, card_fingerprint

BATCH = int(os.environ.get("IMPORT_BATCH", "50000"))
READ_CHUNK = int(os.environ.get("IMPORT_READ_CHUNK", "20000"))
WORKERS = int(os.environ.get("IMPORT_WORKERS", str(max(2, (os.cpu_count() or 4) - 1))))
DROP_INDEXES = os.environ.get("IMPORT_DROP_INDEXES", "1").strip() not in ("0", "false", "no")

_CARD_PREFIX = re.compile(r"^\d{13,19}\|")

STAGING_DDL = """
CREATE UNLOGGED TABLE IF NOT EXISTS entries_import_staging (
    fingerprint   TEXT NOT NULL,
    bin           VARCHAR(6) NOT NULL,
    last4         VARCHAR(4) NOT NULL,
    added_at      TIMESTAMPTZ NOT NULL,
    added_on      DATE NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    attempts      INTEGER NOT NULL,
    pan_length    INTEGER NOT NULL,
    vulgo         VARCHAR(40) NOT NULL,
    cc_full       TEXT NOT NULL
);
"""

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS entries_added_on_idx ON entries (added_on)",
    "CREATE INDEX IF NOT EXISTS entries_last_seen_idx ON entries (last_seen_at DESC)",
)


def resolve_key(conn: psycopg.Connection) -> bytes:
    from_env = os.environ.get("ANTIRETEST_KEY")
    if from_env:
        return from_env.encode("utf-8")
    row = conn.execute("SELECT value FROM meta WHERE key = 'key'").fetchone()
    if not row:
        raise SystemExit("Chave HMAC não encontrada (meta.key ou ANTIRETEST_KEY).")
    return bytes.fromhex(row[0])


def _year(raw: str) -> int | None:
    if len(raw) == 4 and raw.isdigit():
        y = int(raw)
        return y if 2000 <= y <= 2099 else None
    if len(raw) == 2 and raw.isdigit():
        y = 2000 + int(raw)
        return y if 2000 <= y <= 2099 else None
    return None


def _month(raw: str) -> int | None:
    if not raw.isdigit():
        return None
    m = int(raw)
    return m if 1 <= m <= 12 else None


def _parse_fast(stripped: str) -> tuple[str, str] | None:
    """Retorna (pan, cc_full) ou None se não for linha pipe padrão."""
    if not _CARD_PREFIX.match(stripped):
        return None
    parts = stripped.split("|")
    if len(parts) < 4:
        return None
    pan = parts[0].strip()
    if not looks_like_pan(pan):
        return None
    month = _month(parts[1].strip())
    year = _year(parts[2].strip())
    cvv = re.sub(r"\D", "", parts[3])[:4]
    if month is None or year is None:
        return None
    cvv_len = 4 if len(pan) == 15 and pan.startswith(("34", "37")) else 3
    if len(cvv) != cvv_len:
        return None
    cc_full = format_cc_full(pan, month, year, cvv)
    return pan, cc_full


_KEY: bytes | None = None
_MOMENT_ISO: str = ""
_MOMENT_DATE: str = ""


def _init_worker(key_hex: str, moment_iso: str, moment_date: str) -> None:
    global _KEY, _MOMENT_ISO, _MOMENT_DATE
    _KEY = bytes.fromhex(key_hex)
    _MOMENT_ISO = moment_iso
    _MOMENT_DATE = moment_date


def _lines_to_rows(lines: list[str]) -> tuple[list[tuple], dict[str, int]]:
    assert _KEY is not None
    stats = {"invalid": 0, "empty": 0, "slow": 0}
    unique: dict[str, tuple] = {}
    moment = datetime.fromisoformat(_MOMENT_ISO)
    moment_d = date.fromisoformat(_MOMENT_DATE)

    for line in lines:
        stripped = line.strip()
        if not stripped:
            stats["empty"] += 1
            continue
        parsed = _parse_fast(stripped)
        if parsed is None:
            try:
                entry = parse_entry(stripped)
                cc_full = f"{entry.pan}|{entry.month:02d}|{entry.year}|{entry.cvv}"
                parsed = (entry.pan, cc_full)
                stats["slow"] += 1
            except InvalidNumberError:
                stats["invalid"] += 1
                continue

        pan, cc_full = parsed
        fp = card_fingerprint(cc_full, _KEY)
        unique.setdefault(
            fp,
            (
                fp,
                pan[:6],
                pan[-4:],
                moment,
                moment_d,
                moment,
                1,
                len(pan),
                "",
                cc_full,
            ),
        )
    return list(unique.values()), stats


def copy_flush(conn: psycopg.Connection, rows: list[tuple]) -> int:
    if not rows:
        return 0
    conn.execute("TRUNCATE entries_import_staging")
    cols = (
        "fingerprint",
        "bin",
        "last4",
        "added_at",
        "added_on",
        "last_seen_at",
        "attempts",
        "pan_length",
        "vulgo",
        "cc_full",
    )
    with conn.cursor() as cur:
        with cur.copy(f"COPY entries_import_staging ({', '.join(cols)}) FROM STDIN") as copy:
            for row in rows:
                copy.write_row(row)
        cur.execute(
            "INSERT INTO entries"
            f" ({', '.join(cols)})"
            " SELECT DISTINCT ON (fingerprint)"
            f" {', '.join(cols)}"
            " FROM entries_import_staging"
            " ORDER BY fingerprint"
            " ON CONFLICT (fingerprint) DO NOTHING"
        )
        inserted = max(int(cur.rowcount), 0)
    conn.commit()
    return inserted


def tune_session(conn: psycopg.Connection) -> None:
    conn.execute("SET synchronous_commit TO off")
    conn.execute("SET work_mem TO '256MB'")


def drop_secondary_indexes(conn: psycopg.Connection) -> None:
    if not DROP_INDEXES:
        return
    conn.execute("DROP INDEX IF EXISTS entries_added_on_idx")
    conn.execute("DROP INDEX IF EXISTS entries_last_seen_idx")
    conn.commit()
    print("índices secundários removidos (serão recriados ao final)", flush=True)


def restore_secondary_indexes(conn: psycopg.Connection) -> None:
    if not DROP_INDEXES:
        return
    for ddl in _INDEXES:
        conn.execute(ddl)
    conn.commit()
    print("índices secundários recriados", flush=True)


def import_one_file(
    conn: psycopg.Connection,
    pool: ProcessPoolExecutor,
    key: bytes,
    path: Path,
    moment: datetime,
) -> dict[str, int]:
    stats = {
        "lines": 0,
        "imported": 0,
        "duplicates": 0,
        "invalid": 0,
        "empty": 0,
        "slow": 0,
    }
    pending: list[tuple] = []
    t0 = time.time()
    print(
        f"importando {path} (COPY lote {BATCH}, read {READ_CHUNK}, workers {WORKERS})...",
        flush=True,
    )

    key_hex = key.hex()
    moment_iso = moment.isoformat()
    moment_date = moment.date().isoformat()

    with path.open(encoding="utf-8-sig", errors="replace") as handle:
        while True:
            chunk = []
            for _ in range(READ_CHUNK):
                line = handle.readline()
                if not line:
                    break
                chunk.append(line)
            if not chunk:
                break
            stats["lines"] += len(chunk)
            for part_rows, part_stats in pool.map(_lines_to_rows, _split_even(chunk, WORKERS)):
                stats["invalid"] += part_stats["invalid"]
                stats["empty"] += part_stats["empty"]
                stats["slow"] += part_stats["slow"]
                pending.extend(part_rows)
            while len(pending) >= BATCH:
                batch = pending[:BATCH]
                pending = pending[BATCH:]
                unique: dict[str, tuple] = {}
                for row in batch:
                    unique.setdefault(row[0], row)
                payload = list(unique.values())
                inserted = copy_flush(conn, payload)
                stats["imported"] += inserted
                stats["duplicates"] += len(payload) - inserted
            if stats["lines"] % 1_000_000 == 0:
                elapsed = max(time.time() - t0, 0.001)
                rate = stats["lines"] / elapsed
                print(
                    f"  {path.name}: {stats['lines']:,} linhas · "
                    f"{stats['imported']:,} novo(s) · {rate:,.0f} lin/s".replace(",", "."),
                    flush=True,
                )

    if pending:
        unique = {row[0]: row for row in pending}
        payload = list(unique.values())
        inserted = copy_flush(conn, payload)
        stats["imported"] += inserted
        stats["duplicates"] += len(payload) - inserted

    elapsed = max(time.time() - t0, 0.001)
    print(
        f"concluído {path.name}: {stats['imported']:,} importado(s) · "
        f"{stats['duplicates']:,} dup · {stats['invalid']:,} inválido(s) · "
        f"{stats['lines']:,} linhas · {elapsed:.0f}s".replace(",", "."),
        flush=True,
    )
    return stats


def _split_even(lines: list[str], n: int) -> list[list[str]]:
    if n <= 1:
        return [lines]
    size = max(1, (len(lines) + n - 1) // n)
    return [lines[i : i + size] for i in range(0, len(lines), size)]


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        raw = os.environ.get("IMPORT_PATHS", "").strip()
        if raw:
            paths = [Path(p.strip()) for p in raw.split(",") if p.strip()]
    if not paths:
        print("Uso: import_txt_to_postgres_fast.py arquivo.txt [...]", file=sys.stderr)
        return 2

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL obrigatório", file=sys.stderr)
        return 2

    for path in paths:
        if not path.is_file():
            print(f"arquivo não encontrado: {path}", file=sys.stderr)
            return 2

    moment = datetime.now(timezone.utc)
    totals = {"lines": 0, "imported": 0, "duplicates": 0, "invalid": 0, "empty": 0, "slow": 0}

    with psycopg.connect(dsn) as conn:
        conn.execute(PG_SCHEMA)
        conn.execute(STAGING_DDL)
        conn.commit()
        tune_session(conn)
        key = resolve_key(conn)
        drop_secondary_indexes(conn)

        with ProcessPoolExecutor(
            max_workers=WORKERS,
            initializer=_init_worker,
            initargs=(key.hex(), moment.isoformat(), moment.date().isoformat()),
        ) as pool:
            for path in paths:
                st = import_one_file(conn, pool, key, path, moment)
                for k in totals:
                    totals[k] += st.get(k, 0)

        restore_secondary_indexes(conn)
        pg_total = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        print(f"postgres entries: {pg_total:,}".replace(",", "."))

    print(
        f"TOTAL: {totals['imported']:,} importado(s) · {totals['duplicates']:,} dup · "
        f"{totals['invalid']:,} inválido(s) · {totals['lines']:,} linha(s)".replace(",", ".")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
