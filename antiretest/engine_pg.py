"""Motor anti-retest com PostgreSQL."""

from __future__ import annotations

import os
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .core import (
    InvalidNumberError,
    format_cc_full_from_entry,
    fingerprint,
    is_fingerprint_line,
    mask,
    mask_vulgo,
    parse_entry,
    sanitize_vulgo,
)
from .daily_log import MARK_EXPIRED, MARK_INVALID, MARK_KNOWN, MARK_NEW, DailyLog

PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    fingerprint   TEXT PRIMARY KEY,
    bin           VARCHAR(6) NOT NULL,
    last4         VARCHAR(4) NOT NULL,
    added_at      TIMESTAMPTZ NOT NULL,
    added_on      DATE NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 1,
    pan_length    INTEGER NOT NULL DEFAULT 16,
    vulgo         VARCHAR(40) NOT NULL DEFAULT '',
    cc_full       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS entries_added_on_idx ON entries (added_on);
CREATE INDEX IF NOT EXISTS entries_last_seen_idx ON entries (last_seen_at DESC);
"""


FETCH_CHUNK = 10_000
FP_SCHEME = "cartao"
# Recontar a tabela inteira é caro; entre recontagens os números andam por delta.
STATS_TTL = float(os.environ.get("ANTIRETEST_STATS_TTL", "60"))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(raw: str | datetime) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _row_to_check_dict(row: dict[str, Any], *, moment: datetime, record: bool) -> dict[str, Any]:
    added_at = _parse_ts(row["added_at"])
    days_since = (moment.date() - added_at.date()).days
    pan_length = int(row["pan_length"])
    masked = f"{row['bin']}{'*' * max(0, pan_length - 10)}{row['last4']}"
    attempts = int(row["attempts"]) + (1 if record else 0)
    return {
        "masked": masked,
        "fingerprint": row["fingerprint"],
        "is_retest": True,
        "status": "known",
        "recorded": False,
        "added_on": added_at.date().isoformat(),
        "days_since_added": days_since,
        "attempts": attempts,
        "expiry": "—",
        "expired": False,
        "vulgo": sanitize_vulgo(row.get("vulgo") or ""),
        # Quem consulta por hash não enviou validade/CVV; o guardado nunca sai daqui.
        "cc_full": "",
    }


def card_fingerprint(cc_full: str, key: bytes) -> str:
    """Identidade do registro: o cartão inteiro (número|mês|ano|cvv), não só o número."""
    return fingerprint(cc_full, key)


class AntiRetestPg:
    def __init__(
        self,
        dsn: str | None = None,
        *,
        key: bytes | None = None,
        log_dir: str | None = None,
        pool: ConnectionPool | None = None,
    ) -> None:
        self._dsn = dsn or os.environ["DATABASE_URL"]
        self._pool = pool or ConnectionPool(self._dsn, min_size=1, max_size=20, kwargs={"row_factory": dict_row})
        self._owns_pool = pool is None
        with self._pool.connection() as conn:
            conn.execute(PG_SCHEMA)
            conn.commit()
        self._key = key or self._resolve_key()
        self._check_fp_scheme()
        log_env = os.environ.get("ANTIRETEST_LOG_DIR", "")
        if log_env == "-":
            self._log = None
        elif log_dir is not None:
            self._log = DailyLog(log_dir)
        elif log_env:
            self._log = DailyLog(log_env)
        else:
            self._log = None
        self._init_stats_cache()

    def _init_stats_cache(self) -> None:
        self._stats_lock = threading.Lock()
        self._stats_cache: dict[str, Any] | None = None
        self._stats_at = 0.0
        self._stats_refreshing = False

    def _check_fp_scheme(self) -> None:
        """Base antiga (chave só pelo número) misturada com a nova duplicaria cartões."""
        with self._pool.connection() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'fp_scheme'").fetchone()
            if row and row["value"] == FP_SCHEME:
                return
            if conn.execute("SELECT EXISTS (SELECT 1 FROM entries)").fetchone()["exists"]:
                raise RuntimeError(
                    "Base com fingerprints antigos (só o número do cartão). Rode uma vez:"
                    " docker compose --profile migrate-fp run --rm migrate-fp"
                )
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('fp_scheme', %s)"
                " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                (FP_SCHEME,),
            )
            conn.commit()

    def close(self) -> None:
        if self._owns_pool:
            self._pool.close()

    def _resolve_key(self) -> bytes:
        from_env = os.environ.get("ANTIRETEST_KEY")
        if from_env:
            return from_env.encode("utf-8")
        with self._pool.connection() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'key'").fetchone()
            if row:
                return bytes.fromhex(row["value"])
            generated = secrets.token_bytes(32)
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('key', %s) ON CONFLICT (key) DO NOTHING",
                (generated.hex(),),
            )
            conn.commit()
            row = conn.execute("SELECT value FROM meta WHERE key = 'key'").fetchone()
            return bytes.fromhex(row["value"])

    def stats(self) -> dict[str, Any]:
        with self._stats_lock:
            cache = self._stats_cache
            vencido = time.monotonic() - self._stats_at > STATS_TTL
            atualizar = cache is not None and vencido and not self._stats_refreshing
            if atualizar:
                self._stats_refreshing = True
        if cache is None:
            return self._refresh_stats()
        if atualizar:
            threading.Thread(target=self._refresh_stats, daemon=True).start()
        return dict(cache)

    def _refresh_stats(self) -> dict[str, Any]:
        try:
            fresh = self._query_stats()
        finally:
            with self._stats_lock:
                self._stats_refreshing = False
        with self._stats_lock:
            self._stats_cache = fresh
            self._stats_at = time.monotonic()
        return dict(fresh)

    def _apply_stats_delta(
        self,
        inserts: dict[str, dict[str, Any]],
        bumps: dict[str, int],
        rows: dict[str, dict[str, Any]],
        moment: datetime,
    ) -> None:
        with self._stats_lock:
            cache = self._stats_cache
            if cache is None:
                return
            cache["total"] += len(inserts)
            cache["attempts"] += sum(r["attempts"] for r in inserts.values())
            cache["attempts"] += sum(bumps.values())
            cache["repetidos"] = max(0, cache["attempts"] - cache["total"])
            cache["retested"] += sum(1 for r in inserts.values() if r["attempts"] > 1)
            cache["retested"] += sum(
                1 for fp in bumps if fp in rows and int(rows[fp]["attempts"]) == 1
            )
            if inserts:
                hoje = moment.date().isoformat()
                cache["last_day"] = max(cache["last_day"] or hoje, hoje)
                cache["first_day"] = cache["first_day"] or hoje

    def _query_stats(self) -> dict[str, Any]:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total, COALESCE(SUM(attempts), 0) AS attempts,"
                " MIN(added_on) AS first_day, MAX(added_on) AS last_day FROM entries"
            ).fetchone()
            retested = conn.execute(
                "SELECT COUNT(*) AS n FROM entries WHERE attempts > 1"
            ).fetchone()["n"]
        total = int(row["total"] or 0)
        attempts = int(row["attempts"] or 0)
        first_day = row["first_day"]
        last_day = row["last_day"]
        return {
            "total": total,
            "attempts": attempts,
            "repetidos": max(0, attempts - total),
            "retested": int(retested),
            "first_day": first_day.isoformat() if hasattr(first_day, "isoformat") else first_day,
            "last_day": last_day.isoformat() if hasattr(last_day, "isoformat") else last_day,
        }

    def check_by_fingerprint(
        self,
        fp_value: str,
        *,
        record: bool = True,
        raw_line: str | None = None,
    ) -> dict[str, Any]:
        moment = _now_utc()
        fp = str(fp_value).strip().lower()
        with self._pool.connection() as conn:
            row = conn.execute("SELECT * FROM entries WHERE fingerprint = %s", (fp,)).fetchone()
            if row is None:
                raise InvalidNumberError("Hash não encontrado na base.")
            payload = _row_to_check_dict(row, moment=moment, record=record)
            if record:
                conn.execute(
                    "UPDATE entries SET attempts = %s, last_seen_at = %s WHERE fingerprint = %s",
                    (payload["attempts"], moment, fp),
                )
                conn.commit()
                if self._log:
                    self._log.append(raw_line or fp, MARK_KNOWN, now=moment)
        return payload

    def check(
        self,
        number: str,
        *,
        record: bool = True,
        raw_line: str | None = None,
        vulgo: str = "",
    ) -> dict[str, Any]:
        moment = _now_utc()
        vulgo = sanitize_vulgo(vulgo)
        try:
            entry = parse_entry(number)
        except InvalidNumberError:
            if record and self._log:
                self._log.append(raw_line or number, MARK_INVALID, now=moment)
            raise
        digits = entry.pan
        cc_full = format_cc_full_from_entry(entry)
        expiry = entry.expiry
        expired = entry.is_expired(moment.astimezone().date())
        marcas = (MARK_EXPIRED,) if expired else ()
        fp = card_fingerprint(cc_full, self._key)

        with self._pool.connection() as conn:
            row = conn.execute("SELECT * FROM entries WHERE fingerprint = %s", (fp,)).fetchone()
            if row is None:
                if record:
                    conn.execute(
                        "INSERT INTO entries"
                        " (fingerprint, bin, last4, added_at, added_on, last_seen_at,"
                        " attempts, pan_length, vulgo, cc_full)"
                        " VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s, %s)",
                        (
                            fp,
                            digits[:6],
                            digits[-4:],
                            moment,
                            moment.date(),
                            moment,
                            len(digits),
                            vulgo,
                            cc_full,
                        ),
                    )
                    conn.commit()
                    if self._log:
                        self._log.append(raw_line or number, MARK_NEW, *marcas, now=moment)
                return {
                    "masked": mask(digits),
                    "fingerprint": fp,
                    "is_retest": False,
                    "status": "new",
                    "recorded": record,
                    "added_on": moment.date().isoformat(),
                    "days_since_added": 0,
                    "attempts": 1,
                    "expiry": expiry,
                    "expired": expired,
                    "vulgo": vulgo,
                    "cc_full": cc_full,
                }

            added_at = _parse_ts(row["added_at"])
            days_since = (moment.date() - added_at.date()).days
            attempts = int(row["attempts"]) + (1 if record else 0)
            vulgo_gravado = sanitize_vulgo(row.get("vulgo") or "")
            if record:
                conn.execute(
                    "UPDATE entries SET attempts = %s, last_seen_at = %s WHERE fingerprint = %s",
                    (attempts, moment, fp),
                )
                conn.commit()
                if self._log:
                    self._log.append(raw_line or number, MARK_KNOWN, *marcas, now=moment)

            return {
                "masked": mask(digits),
                "fingerprint": fp,
                "is_retest": True,
                "status": "known",
                "recorded": False,
                "added_on": added_at.date().isoformat(),
                "days_since_added": days_since,
                "attempts": attempts,
                "expiry": expiry,
                "expired": expired,
                "vulgo": vulgo_gravado,
                "cc_full": cc_full,
            }

    def _fetch_rows(self, fps: set[str]) -> dict[str, dict[str, Any]]:
        """Registros existentes para os fingerprints do lote, em poucas consultas."""
        if not fps:
            return {}
        lista = sorted(fps)
        rows: dict[str, dict[str, Any]] = {}
        with self._pool.connection() as conn:
            for i in range(0, len(lista), FETCH_CHUNK):
                cursor = conn.execute(
                    "SELECT fingerprint, bin, last4, added_at, attempts, pan_length, vulgo, cc_full"
                    " FROM entries WHERE fingerprint = ANY(%s)",
                    (lista[i : i + FETCH_CHUNK],),
                )
                for row in cursor:
                    rows[row["fingerprint"]] = row
        return rows

    def _persist(
        self,
        inserts: dict[str, dict[str, Any]],
        bumps: dict[str, int],
        moment: datetime,
    ) -> None:
        """Grava o lote inteiro numa transação; ordem fixa evita deadlock entre lotes."""
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                if inserts:
                    cur.executemany(
                        "INSERT INTO entries"
                        " (fingerprint, bin, last4, added_at, added_on, last_seen_at,"
                        " attempts, pan_length, vulgo, cc_full)"
                        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                        " ON CONFLICT (fingerprint) DO UPDATE SET"
                        " attempts = entries.attempts + EXCLUDED.attempts,"
                        " last_seen_at = EXCLUDED.last_seen_at",
                        [
                            (
                                fp, r["bin"], r["last4"], moment, moment.date(), moment,
                                r["attempts"], r["pan_length"], r["vulgo"], r["cc_full"],
                            )
                            for fp, r in sorted(inserts.items())
                        ],
                    )
                if bumps:
                    cur.executemany(
                        "UPDATE entries SET attempts = attempts + %s, last_seen_at = %s"
                        " WHERE fingerprint = %s",
                        [(n, moment, fp) for fp, n in sorted(bumps.items())],
                    )
            conn.commit()

    def check_many(
        self,
        numbers: list[str],
        *,
        record_new: bool = False,
        vulgo: str = "",
    ) -> dict[str, Any]:
        moment = _now_utc()
        hoje = moment.astimezone().date()
        vulgo = sanitize_vulgo(vulgo)
        result: dict[str, Any] = {"new": [], "known": [], "duplicated": [], "invalid": [], "total": 0}

        parsed: list[tuple[int, str, str | None, Any]] = []
        for index, number in enumerate(numbers):
            raw = str(number).strip()
            if not raw:
                continue
            result["total"] += 1
            if is_fingerprint_line(raw):
                parsed.append((index + 1, raw, raw.lower(), None))
                continue
            try:
                entry = parse_entry(raw)
            except InvalidNumberError as err:
                parsed.append((index + 1, raw, None, str(err)))
                continue
            fp = card_fingerprint(format_cc_full_from_entry(entry), self._key)
            parsed.append((index + 1, raw, fp, entry))

        rows = self._fetch_rows({fp for _, _, fp, _ in parsed if fp})
        inserts: dict[str, dict[str, Any]] = {}
        bumps: dict[str, int] = {}
        seen: dict[str, dict[str, Any]] = {}
        log: list[tuple[str, tuple[str, ...]]] = []

        def bump(fp: str) -> None:
            if fp in inserts:
                inserts[fp]["attempts"] += 1
            else:
                bumps[fp] = bumps.get(fp, 0) + 1

        for line, raw, fp, dado in parsed:
            if fp is None:
                result["invalid"].append({"line": line, "reason": dado, "vulgo": None})
                if record_new:
                    log.append((raw, (MARK_INVALID,)))
                continue

            if dado is None:
                if fp in seen:
                    if record_new:
                        bump(fp)
                        log.append((raw, (MARK_KNOWN,)))
                    result["duplicated"].append({
                        "line": line,
                        "masked": seen[fp].get("masked", "hash"),
                        "first_line": seen[fp]["line"],
                        "vulgo": seen[fp].get("vulgo", ""),
                        "cc_full": seen[fp].get("cc_full", ""),
                    })
                    continue
                row = rows.get(fp)
                if row is None:
                    result["invalid"].append(
                        {"line": line, "reason": "Hash não encontrado na base.", "vulgo": None}
                    )
                    if record_new:
                        log.append((raw, (MARK_INVALID,)))
                    continue
                entry_out = _row_to_check_dict(row, moment=moment, record=record_new)
                entry_out["line"] = line
                if record_new:
                    bump(fp)
                    log.append((raw, (MARK_KNOWN,)))
                seen[fp] = {
                    "line": line,
                    "masked": entry_out["masked"],
                    "vulgo": entry_out["vulgo"],
                    "cc_full": entry_out["cc_full"],
                    "is_retest": True,
                }
                result["known"].append(entry_out)
                continue

            entry = dado
            cc_full = format_cc_full_from_entry(entry)
            expired = entry.is_expired(hoje)
            marcas = (MARK_EXPIRED,) if expired else ()

            if fp in seen:
                if record_new:
                    if seen[fp]["is_retest"]:
                        bump(fp)
                        log.append((raw, (MARK_KNOWN,)))
                    else:
                        log.append((raw, (MARK_KNOWN, *marcas)))
                result["duplicated"].append({
                    "line": line,
                    "masked": mask(entry.pan),
                    "first_line": seen[fp]["line"],
                    "vulgo": seen[fp].get("vulgo", ""),
                    "cc_full": cc_full,
                })
                continue

            row = rows.get(fp)
            if row is None:
                if record_new:
                    inserts[fp] = {
                        "bin": entry.pan[:6],
                        "last4": entry.pan[-4:],
                        "attempts": 1,
                        "pan_length": len(entry.pan),
                        "vulgo": vulgo,
                        "cc_full": cc_full,
                    }
                    log.append((raw, (MARK_NEW, *marcas)))
                entry_out = {
                    "masked": mask(entry.pan),
                    "fingerprint": fp,
                    "is_retest": False,
                    "status": "new",
                    "recorded": record_new,
                    "added_on": moment.date().isoformat(),
                    "days_since_added": 0,
                    "attempts": 1,
                    "expiry": entry.expiry,
                    "expired": expired,
                    "vulgo": vulgo,
                    "cc_full": cc_full,
                }
                result["new"].append(entry_out)
            else:
                added_at = _parse_ts(row["added_at"])
                if record_new:
                    bump(fp)
                    log.append((raw, (MARK_KNOWN, *marcas)))
                entry_out = {
                    "masked": mask(entry.pan),
                    "fingerprint": fp,
                    "is_retest": True,
                    "status": "known",
                    "recorded": False,
                    "added_on": added_at.date().isoformat(),
                    "days_since_added": (moment.date() - added_at.date()).days,
                    "attempts": int(row["attempts"]) + (1 if record_new else 0),
                    "expiry": entry.expiry,
                    "expired": expired,
                    "vulgo": sanitize_vulgo(row.get("vulgo") or ""),
                    "cc_full": cc_full,
                }
                result["known"].append(entry_out)
            entry_out["line"] = line
            seen[fp] = {
                "line": line,
                "vulgo": entry_out["vulgo"],
                "cc_full": entry_out["cc_full"],
                "is_retest": entry_out["is_retest"],
            }

        if record_new and (inserts or bumps):
            self._persist(inserts, bumps, moment)
            self._apply_stats_delta(inserts, bumps, rows, moment)
        if self._log and log:
            self._log.append_many(log, now=moment)
        return result
