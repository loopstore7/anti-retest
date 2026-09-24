"""Motor anti-retest com PostgreSQL."""

from __future__ import annotations

import os
import secrets
from datetime import date, datetime, timezone
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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(raw: str | datetime) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_expired(month: int, year: int, today: date | None = None) -> bool:
    hoje = today or date.today()
    return (year, month) < (hoje.year, hoje.month)


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
        "cc_full": str(row.get("cc_full") or "").strip(),
    }


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
        log_env = os.environ.get("ANTIRETEST_LOG_DIR", "")
        if log_env == "-":
            self._log = None
        elif log_dir is not None:
            self._log = DailyLog(log_dir)
        elif log_env:
            self._log = DailyLog(log_env)
        else:
            self._log = None

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
        fp = fingerprint(digits, self._key)

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
                    "UPDATE entries SET attempts = %s, last_seen_at = %s, cc_full = %s"
                    " WHERE fingerprint = %s",
                    (attempts, moment, cc_full, fp),
                )
                conn.commit()
                if self._log:
                    self._log.append(raw_line or number, MARK_KNOWN, *marcas, now=moment)
            else:
                cc_full = str(row.get("cc_full") or "").strip() or cc_full

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

    def _bump_attempts(
        self,
        fp: str,
        raw_line: str | None = None,
        cc_full: str = "",
    ) -> None:
        moment = _now_utc()
        with self._pool.connection() as conn:
            if cc_full:
                conn.execute(
                    "UPDATE entries SET attempts = attempts + 1, last_seen_at = %s, cc_full = %s"
                    " WHERE fingerprint = %s",
                    (moment, cc_full, fp),
                )
            else:
                conn.execute(
                    "UPDATE entries SET attempts = attempts + 1, last_seen_at = %s WHERE fingerprint = %s",
                    (moment, fp),
                )
            conn.commit()
        if self._log and raw_line:
            self._log.append(raw_line, MARK_KNOWN, now=moment)

    def check_many(
        self,
        numbers: list[str],
        *,
        record_new: bool = False,
        vulgo: str = "",
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"new": [], "known": [], "duplicated": [], "invalid": [], "total": 0}
        seen: dict[str, dict[str, Any]] = {}
        vulgo = sanitize_vulgo(vulgo)

        for index, number in enumerate(numbers):
            number = str(number).strip()
            if not number:
                continue
            line = index + 1
            result["total"] += 1

            if is_fingerprint_line(number):
                fp = number.strip().lower()
                if fp in seen:
                    if record_new:
                        self._bump_attempts(fp, number)
                    result["duplicated"].append({
                        "line": line,
                        "masked": seen[fp].get("masked", "hash"),
                        "first_line": seen[fp]["line"],
                        "vulgo": seen[fp].get("vulgo", ""),
                        "cc_full": seen[fp].get("cc_full", ""),
                    })
                    continue
                try:
                    entry = self.check_by_fingerprint(number, record=record_new, raw_line=number)
                    entry["line"] = line
                except InvalidNumberError as err:
                    result["invalid"].append({"line": line, "reason": str(err), "vulgo": None})
                    if record_new and self._log:
                        self._log.append(number, MARK_INVALID)
                    continue
                seen[fp] = {
                    "line": line,
                    "masked": entry.get("masked", ""),
                    "vulgo": entry.get("vulgo", ""),
                    "cc_full": entry.get("cc_full", ""),
                    "is_retest": True,
                }
                result["known"].append(entry)
                continue

            try:
                entry_parsed = parse_entry(number)
            except InvalidNumberError as err:
                result["invalid"].append({"line": line, "reason": str(err), "vulgo": None})
                if record_new and self._log:
                    self._log.append(number, MARK_INVALID)
                continue

            fp = fingerprint(entry_parsed.pan, self._key)
            cc_full = format_cc_full_from_entry(entry_parsed)
            if fp in seen:
                if record_new and seen[fp].get("is_retest"):
                    self._bump_attempts(fp, number, cc_full)
                elif record_new and self._log:
                    marcas = [MARK_KNOWN]
                    if _is_expired(entry_parsed.month, entry_parsed.year):
                        marcas.append(MARK_EXPIRED)
                    self._log.append(number, *marcas)
                result["duplicated"].append({
                    "line": line,
                    "masked": mask(entry_parsed.pan),
                    "first_line": seen[fp]["line"],
                    "vulgo": seen[fp].get("vulgo", ""),
                    "cc_full": seen[fp].get("cc_full", cc_full),
                })
                continue

            entry = self.check(number, record=record_new, raw_line=number, vulgo=vulgo)
            entry["line"] = line
            seen[fp] = {
                "line": line,
                "vulgo": entry.get("vulgo", ""),
                "cc_full": entry.get("cc_full", cc_full),
                "is_retest": entry.get("is_retest", False),
            }
            if entry["is_retest"]:
                result["known"].append(entry)
            else:
                result["new"].append(entry)

        return result
