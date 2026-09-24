"""Núcleo do anti-retest: validação, fingerprint e persistência."""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest, new as hmac_new
from pathlib import Path

from .daily_log import MARK_EXPIRED, MARK_INVALID, MARK_KNOWN, MARK_NEW, DailyLog

PAN_LENGTH = 16
AMEX_LENGTH = 15
AMEX_PREFIXES = ("34", "37")
PAN_LENGTHS = (PAN_LENGTH, AMEX_LENGTH)
CVV_LENGTH = 3
AMEX_CVV_LENGTH = 4
YEAR_RANGE = (2000, 2099)

DEFAULT_DB_PATH = Path("antiretest.db")
DEFAULT_SEED_PATH = Path("db.txt")

# (linha como veio no arquivo, valores do INSERT, cartão vencido) — None nos
# valores = linha inválida, que entra no lote só para aparecer no txt do dia.
_ImportRow = tuple[str, tuple[str, str, str, str, str, str, int, int, str] | None, bool]

_NON_DIGITS = re.compile(r"[\s.\-_]+")
_FIELD_SEPARATORS = re.compile(r"[|;,:/\\]+")
_DIGIT_RUN = re.compile(r"\d+")
# Linha estranha com muitos números: além disso não vale procurar combinação.
_MAX_TOKENS = 12

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    fingerprint   TEXT PRIMARY KEY,
    bin           TEXT NOT NULL,
    last4         TEXT NOT NULL,
    added_at      TEXT NOT NULL,
    added_on      TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 1,
    pan_length    INTEGER NOT NULL DEFAULT 16,
    vulgo         TEXT NOT NULL DEFAULT '',
    cc_full       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS entries_added_on_idx ON entries (added_on);
"""


class InvalidNumberError(ValueError):
    """Linha que não traz um cartão completo: PAN, validade e CVV válidos."""


@dataclass(frozen=True)
class CardEntry:
    """Cartão completo lido de uma linha: é isso que o anti-retest aceita."""

    pan: str
    month: int
    year: int
    cvv: str

    @property
    def is_amex(self) -> bool:
        return is_amex(self.pan)

    @property
    def expiry(self) -> str:
        return f"{self.month:02d}/{self.year}"

    def is_expired(self, today: date | None = None) -> bool:
        hoje = today or date.today()
        return (self.year, self.month) < (hoje.year, hoje.month)


@dataclass(frozen=True)
class CheckResult:
    """Veredito de uma consulta ao anti-retest."""

    masked: str
    fingerprint: str
    is_retest: bool
    added_at: datetime
    added_on: date
    last_seen_at: datetime
    attempts: int
    days_since_added: int
    expiry: str
    expired: bool
    vulgo: str = ""
    cc_full: str = ""

    @property
    def status(self) -> str:
        return "known" if self.is_retest else "new"

    def describe(self) -> str:
        vencido = " · VENCIDO" if self.expired else ""
        if not self.is_retest:
            quem = f" · {self.vulgo}" if self.vulgo else ""
            return (
                f"{self.masked}: NOVO — registrado em {self.added_on.isoformat()}"
                f" (validade {self.expiry}){quem}{vencido}"
            )
        testado = mask_vulgo(self.vulgo)
        quem = f" · Testado por: {testado}" if testado else ""
        return (
            f"{self.masked}: JÁ NO BANCO — adicionado em {self.added_on.isoformat()}"
            f" ({self.days_since_added}d atrás), {self.attempts} tentativa(s)"
            f" (validade {self.expiry}){quem}{vencido}"
        )


def sanitize_vulgo(raw: str) -> str:
    """Nome/vulgo do cliente: limpa controle e corta em 40 caracteres."""
    limpo = "".join(ch for ch in str(raw).strip() if ord(ch) >= 32 or ch in "\t")
    limpo = limpo.replace("\t", " ").strip()
    return limpo[:40]


def format_cc_full(pan: str, month: int, year: int, cvv: str) -> str:
    """Linha completa do cartão: PAN|MM|AAAA|CVV."""
    return f"{pan}|{month:02d}|{year}|{cvv}"


def format_cc_full_from_entry(entry: CardEntry) -> str:
    return format_cc_full(entry.pan, entry.month, entry.year, entry.cvv)


def mask_vulgo(raw: str) -> str:
    """Mascara vulgo/nome da store: só as 3 primeiras letras visíveis (ex.: Sexta → Sex**)."""
    vulgo = sanitize_vulgo(raw)
    if not vulgo:
        return ""
    tamanho = len(vulgo)
    if tamanho <= 2:
        return vulgo[:1] + "*"
    if tamanho <= 3:
        return vulgo
    return vulgo[:3] + "*" * (tamanho - 3)


def is_fingerprint_line(line: str) -> bool:
    """Linha com fingerprint SHA-256 (64 hex) para consulta direta."""
    return bool(re.fullmatch(r"[a-f0-9]{64}", str(line).strip(), re.IGNORECASE))


def is_amex(pan: str) -> bool:
    return len(pan) == AMEX_LENGTH and pan.startswith(AMEX_PREFIXES)


def cvv_length(pan: str) -> int:
    """Amex usa CVV de 4 dígitos; as outras bandeiras, 3."""
    return AMEX_CVV_LENGTH if is_amex(pan) else CVV_LENGTH


def looks_like_pan(digits: str) -> bool:
    """16 dígitos, ou 15 começando em 34/37 (Amex), sempre com Luhn válido."""
    if len(digits) == AMEX_LENGTH:
        return digits.startswith(AMEX_PREFIXES) and luhn_ok(digits)
    if len(digits) == PAN_LENGTH:
        return luhn_ok(digits)
    return False


def parse_entry(line: str) -> CardEntry:
    """Lê a linha completa: PAN, validade e CVV, nenhum deles opcional.

    Aceita o que vem em volta (``Reprovada PAN|MM|AA|CVV - Refused``) e os
    separadores ``|``, ``;``, ``,``, ``:``, ``/`` e ``\\``. Dentro de um campo,
    espaço, ponto, hífen e sublinhado são só formatação.
    """
    tokens = _numeric_tokens(str(line))
    entrada = _from_fields(tokens) or _from_single_run(tokens)
    if entrada is None:
        raise InvalidNumberError(_explain(tokens))
    return entrada


def normalize(number: str) -> str:
    """Extrai só o PAN de uma linha e valida o Luhn.

    Caminho de ``forget`` e ``verify``, onde exigir validade e CVV não faria
    sentido: para gravar no banco, quem manda é ``parse_entry``.
    """
    tokens = _numeric_tokens(str(number))
    for token in tokens:
        if looks_like_pan(token):
            return token
    if len(tokens) == 1:
        for tamanho in PAN_LENGTHS:
            if looks_like_pan(tokens[0][:tamanho]):
                return tokens[0][:tamanho]
    raise InvalidNumberError(_explain_pan(tokens))


def _numeric_tokens(raw: str) -> list[str]:
    """Sequências de dígitos da linha, campo por campo, na ordem."""
    tokens: list[str] = []
    for field in _FIELD_SEPARATORS.split(raw):
        tokens.extend(_DIGIT_RUN.findall(_NON_DIGITS.sub("", field)))
    return tokens


def _from_fields(tokens: list[str]) -> CardEntry | None:
    """Caso normal: cada dado num campo (``PAN|MM|AAAA|CVV``, em qualquer ordem)."""
    limite = tokens[:_MAX_TOKENS]
    for index, token in enumerate(limite):
        if not looks_like_pan(token):
            continue
        resto = limite[:index] + limite[index + 1 :]
        validade = _pick_expiry_and_cvv(resto, cvv_length(token))
        if validade is not None:
            month, year, cvv = validade
            return CardEntry(token, month, year, cvv)
    return None


def _pick_expiry_and_cvv(tokens: list[str], cvv_len: int) -> tuple[int, int, str] | None:
    """Mês, ano e CVV na ordem em que aparecem, ignorando números extras."""
    for index, token in enumerate(tokens):
        juntos = _expiry_from_token(token)
        if juntos is not None:
            cvv = _first_cvv(tokens[index + 1 :], cvv_len)
            if cvv is not None:
                return juntos[0], juntos[1], cvv

        month = _month(token)
        if month is None:
            continue
        for seguinte in range(index + 1, len(tokens)):
            year = _year(tokens[seguinte])
            if year is None:
                continue
            cvv = _first_cvv(tokens[seguinte + 1 :], cvv_len)
            if cvv is not None:
                return month, year, cvv
    return None


def _from_single_run(tokens: list[str]) -> CardEntry | None:
    """Tudo emendado, sem separador (``4111111111111111 12 2028 123``)."""
    if len(tokens) != 1:
        return None
    digits = tokens[0]
    for tamanho in PAN_LENGTHS:
        pan = digits[:tamanho]
        if not looks_like_pan(pan):
            continue
        resto = digits[tamanho:]
        for year_len in (4, 2):
            if len(resto) != 2 + year_len + cvv_length(pan):
                continue
            month = _month(resto[:2])
            year = _year(resto[2 : 2 + year_len])
            if month is not None and year is not None:
                return CardEntry(pan, month, year, resto[2 + year_len :])
    return None


def _expiry_from_token(token: str) -> tuple[int, int] | None:
    """Validade num campo só (``1228`` ou ``122028``)."""
    if len(token) not in (4, 6):
        return None
    month = _month(token[:2])
    year = _year(token[2:])
    if month is None or year is None:
        return None
    return month, year


def _month(token: str) -> int | None:
    if len(token) not in (1, 2) or not token.isdigit():
        return None
    valor = int(token)
    return valor if 1 <= valor <= 12 else None


def _year(token: str) -> int | None:
    """Ano de 2 ou 4 dígitos; 29 vira 2029."""
    if not token.isdigit():
        return None
    if len(token) == 2:
        return 2000 + int(token)
    if len(token) == 4 and YEAR_RANGE[0] <= int(token) <= YEAR_RANGE[1]:
        return int(token)
    return None


def _first_cvv(tokens: list[str], cvv_len: int) -> str | None:
    return next((token for token in tokens if len(token) == cvv_len), None)


def _explain(tokens: list[str]) -> str:
    pan = next((token for token in tokens if looks_like_pan(token)), None)
    if pan is None:
        return _explain_pan(tokens)
    return (
        "falta a validade ou o CVV: envie PAN|MM|AAAA|CVV"
        f" (mês 01-12, ano, CVV de {cvv_length(pan)} dígitos"
        f"{' — Amex' if is_amex(pan) else ''})"
    )


def _explain_pan(tokens: list[str]) -> str:
    if not tokens:
        return "nenhum número na linha"
    return (
        "nenhum cartão válido: são 16 dígitos (ou 15 começando em 34/37, Amex)"
        " com dígito verificador (Luhn) correto"
    )


def luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def mask(digits: str) -> str:
    """BIN + últimos 4, único formato exibível/armazenável em claro."""
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def fingerprint(digits: str, key: bytes) -> str:
    """Hash HMAC-SHA256 do PAN; a linha completa fica em cc_full."""
    return hmac_new(key, digits.encode("ascii"), sha256).hexdigest()


def _parse_ts(raw: str) -> datetime:
    return datetime.fromisoformat(raw)


class AntiRetest:
    """Registra números de 16 dígitos: quem já entrou fica marcado para sempre."""

    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB_PATH,
        *,
        key: bytes | None = None,
        log_dir: str | Path | None = None,
    ) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._key = key or self._resolve_key()
        # Sem log_dir, nada em claro sai daqui; com log_dir, cada linha
        # verificada também vai para o txt do dia, com a marca do resultado.
        self._log = DailyLog(log_dir) if log_dir is not None else None

    def __enter__(self) -> "AntiRetest":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _migrate(self) -> None:
        """Bancos antigos: Amex (pan_length) e depois o vulgo de quem registrou."""
        colunas = {row["name"] for row in self._conn.execute("PRAGMA table_info(entries)")}
        if "pan_length" not in colunas:
            with self._conn:
                self._conn.execute(
                    "ALTER TABLE entries ADD COLUMN pan_length INTEGER NOT NULL DEFAULT 16"
                )
        if "vulgo" not in colunas:
            with self._conn:
                self._conn.execute(
                    "ALTER TABLE entries ADD COLUMN vulgo TEXT NOT NULL DEFAULT ''"
                )
        if "cc_full" not in colunas:
            with self._conn:
                self._conn.execute(
                    "ALTER TABLE entries ADD COLUMN cc_full TEXT NOT NULL DEFAULT ''"
                )

    def _resolve_key(self) -> bytes:
        from_env = os.environ.get("ANTIRETEST_KEY")
        if from_env:
            return from_env.encode("utf-8")
        # Sem chave externa, gera uma por banco: mantém os fingerprints estáveis
        # entre execuções sem exigir configuração.
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'key'").fetchone()
        if row:
            return bytes.fromhex(row["value"])
        generated = secrets.token_bytes(32)
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('key', ?)", (generated.hex(),)
            )
        return generated

    def check_by_fingerprint(
        self,
        fingerprint_value: str,
        *,
        record: bool = True,
        now: datetime | None = None,
    ) -> CheckResult:
        """Consulta por fingerprint (hash SHA-256) já existente na base."""
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        fp = str(fingerprint_value).strip().lower()
        row = self._conn.execute(
            "SELECT * FROM entries WHERE fingerprint = ?", (fp,)
        ).fetchone()
        if row is None:
            raise InvalidNumberError("Hash não encontrado na base.")

        added_at = _parse_ts(row["added_at"])
        days_since = (moment.date() - added_at.date()).days
        attempts = row["attempts"] + (1 if record else 0)
        pan_length = int(row["pan_length"])
        masked = f"{row['bin']}{'*' * (pan_length - 10)}{row['last4']}"
        try:
            vulgo_gravado = sanitize_vulgo(row["vulgo"] or "")
        except (KeyError, IndexError):
            vulgo_gravado = ""
        cc_full = str(row["cc_full"] or "").strip()

        if record:
            with self._conn:
                self._conn.execute(
                    "UPDATE entries SET attempts = ?, last_seen_at = ? WHERE fingerprint = ?",
                    (attempts, moment.isoformat(), fp),
                )
            if self._log is not None:
                self._log.append(fp, MARK_KNOWN, now=moment)

        return CheckResult(
            masked=masked,
            fingerprint=fp,
            is_retest=True,
            added_at=added_at,
            added_on=added_at.date(),
            last_seen_at=moment if record else _parse_ts(row["last_seen_at"]),
            attempts=attempts,
            days_since_added=days_since,
            expiry="—",
            expired=False,
            vulgo=vulgo_gravado,
            cc_full=cc_full,
        )

    def check(
        self,
        number: str,
        *,
        record: bool = True,
        now: datetime | None = None,
        vulgo: str = "",
    ) -> CheckResult:
        """Consulta um número e, por padrão, registra a tentativa."""
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        vulgo = sanitize_vulgo(vulgo)
        try:
            entry = parse_entry(number)
        except InvalidNumberError:
            # A linha não serve para o banco, mas fica registrada no txt do dia.
            if record and self._log is not None:
                self._log.append(str(number), MARK_INVALID, now=moment)
            raise
        digits = entry.pan
        cc_full = format_cc_full_from_entry(entry)
        expired = entry.is_expired(moment.astimezone().date())
        marcas = (MARK_EXPIRED,) if expired else ()
        fp = fingerprint(digits, self._key)

        row = self._conn.execute(
            "SELECT * FROM entries WHERE fingerprint = ?", (fp,)
        ).fetchone()

        if row is None:
            if record:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO entries"
                        " (fingerprint, bin, last4, added_at, added_on, last_seen_at,"
                        " attempts, pan_length, vulgo, cc_full)"
                        " VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                        (
                            fp,
                            digits[:6],
                            digits[-4:],
                            moment.isoformat(),
                            moment.date().isoformat(),
                            moment.isoformat(),
                            len(digits),
                            vulgo,
                            cc_full,
                        ),
                    )
                if self._log is not None:
                    self._log.append(str(number), MARK_NEW, *marcas, now=moment)
            return CheckResult(
                masked=mask(digits),
                fingerprint=fp,
                is_retest=False,
                added_at=moment,
                added_on=moment.date(),
                last_seen_at=moment,
                attempts=1,
                days_since_added=0,
                expiry=entry.expiry,
                expired=expired,
                vulgo=vulgo,
                cc_full=cc_full,
            )

        added_at = _parse_ts(row["added_at"])
        days_since = (moment.date() - added_at.date()).days
        attempts = row["attempts"] + (1 if record else 0)
        try:
            vulgo_gravado = sanitize_vulgo(row["vulgo"] or "")
        except (KeyError, IndexError):
            vulgo_gravado = ""

        if record:
            with self._conn:
                self._conn.execute(
                    "UPDATE entries SET attempts = ?, last_seen_at = ?, cc_full = ?"
                    " WHERE fingerprint = ?",
                    (attempts, moment.isoformat(), cc_full, fp),
                )
            if self._log is not None:
                self._log.append(str(number), MARK_KNOWN, *marcas, now=moment)
        else:
            cc_full = str(row["cc_full"] or "").strip() or cc_full

        return CheckResult(
            masked=mask(digits),
            fingerprint=fp,
            is_retest=True,
            added_at=added_at,
            added_on=added_at.date(),
            last_seen_at=moment if record else _parse_ts(row["last_seen_at"]),
            attempts=attempts,
            days_since_added=days_since,
            expiry=entry.expiry,
            expired=expired,
            vulgo=vulgo_gravado,
            cc_full=cc_full,
        )

    def forget(self, number: str) -> bool:
        """Remove um número do histórico. Retorna True se existia."""
        fp = fingerprint(normalize(number), self._key)
        with self._conn:
            cursor = self._conn.execute("DELETE FROM entries WHERE fingerprint = ?", (fp,))
        return cursor.rowcount > 0

    def purge(self, older_than_days: int, *, now: datetime | None = None) -> int:
        """Apaga registros adicionados há mais de N dias."""
        if older_than_days < 0:
            raise ValueError("older_than_days não pode ser negativo")
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        cutoff = (moment.date() - timedelta(days=older_than_days)).isoformat()
        with self._conn:
            cursor = self._conn.execute("DELETE FROM entries WHERE added_on < ?", (cutoff,))
        return cursor.rowcount

    def recent(self, limit: int = 50, *, now: datetime | None = None) -> list[dict[str, object]]:
        """Últimos registros, do mais recente para o mais antigo."""
        today = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date()
        rows = self._conn.execute(
            "SELECT * FROM entries ORDER BY last_seen_at DESC LIMIT ?", (limit,)
        ).fetchall()
        listagem = []
        for row in rows:
            added_on = date.fromisoformat(row["added_on"])
            days_since = (today - added_on).days
            listagem.append(
                {
                    "masked": f"{row['bin']}{'*' * (row['pan_length'] - 10)}{row['last4']}",
                    "cc_full": str(row["cc_full"] or "").strip(),
                    "added_on": added_on,
                    "days_since_added": days_since,
                    "attempts": row["attempts"],
                    "last_seen_at": _parse_ts(row["last_seen_at"]),
                }
            )
        return listagem

    def stats(self) -> dict[str, object]:
        row = self._conn.execute(
            "SELECT COUNT(*) AS total, SUM(attempts) AS attempts,"
            " MIN(added_on) AS first_day, MAX(added_on) AS last_day FROM entries"
        ).fetchone()
        total = int(row["total"] or 0)
        attempts = int(row["attempts"] or 0)
        retests = self._conn.execute(
            "SELECT COUNT(*) AS n FROM entries WHERE attempts > 1"
        ).fetchone()["n"]
        return {
            "total": total,
            "attempts": attempts,
            "repetidos": max(0, attempts - total),
            "retested": retests,
            "first_day": row["first_day"],
            "last_day": row["last_day"],
        }

    def verify(self, number: str, expected_fingerprint: str) -> bool:
        """Compara um número com um fingerprint já conhecido, sem vazar timing."""
        return compare_digest(fingerprint(normalize(number), self._key), expected_fingerprint)

    def import_file(
        self,
        path: str | Path,
        *,
        now: datetime | None = None,
        batch_size: int = 5000,
    ) -> dict[str, int]:
        """Importa cartões de um arquivo texto (uma linha por entrada).

        Exige o mesmo que a verificação (ex.: ``Reprovada PAN|MM|AA|CVV - Refused``):
        linha sem PAN, sem validade ou sem CVV é ignorada, e duplicatas no
        arquivo ou no banco são puladas.
        """
        if batch_size < 1:
            raise ValueError("batch_size deve ser >= 1")

        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        added_at = moment.isoformat()
        added_on = moment.date().isoformat()
        hoje = moment.astimezone().date()

        stats = {"lines": 0, "imported": 0, "duplicates": 0, "invalid": 0, "empty": 0, "expired": 0}
        batch: list[_ImportRow] = []

        # utf-8-sig: arquivos salvos no Windows costumam vir com BOM, que senão
        # entraria na primeira linha do txt diário.
        with Path(path).open(encoding="utf-8-sig", errors="replace") as handle:
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
                    if self._log is not None:
                        batch.append((stripped, None, False))
                    continue

                digits = entry.pan
                expired = entry.is_expired(hoje)
                if expired:
                    stats["expired"] += 1

                batch.append(
                    (
                        stripped,
                        (
                            fingerprint(digits, self._key),
                            digits[:6],
                            digits[-4:],
                            added_at,
                            added_on,
                            added_at,
                            1,
                            len(digits),
                            format_cc_full_from_entry(entry),
                        ),
                        expired,
                    )
                )
                if len(batch) >= batch_size:
                    inserted, skipped = self._flush_import_batch(batch, moment)
                    stats["imported"] += inserted
                    stats["duplicates"] += skipped
                    batch = []

        if batch:
            inserted, skipped = self._flush_import_batch(batch, moment)
            stats["imported"] += inserted
            stats["duplicates"] += skipped

        return stats

    def _flush_import_batch(self, batch: list[_ImportRow], moment: datetime) -> tuple[int, int]:
        validas = [(line, row) for line, row, _expired in batch if row is not None]
        unique: dict[str, tuple[str, tuple[str, str, str, str, str, str, int, int, str]]] = {}
        for line, row in validas:
            unique.setdefault(row[0], (line, row))

        conhecidos = self._existing_fingerprints(list(unique))
        novos = {fp for fp in unique if fp not in conhecidos}

        with self._conn:
            self._conn.executemany(
                "INSERT INTO entries"
                " (fingerprint, bin, last4, added_at, added_on, last_seen_at,"
                " attempts, pan_length, cc_full)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(fingerprint) DO UPDATE SET cc_full = excluded.cc_full"
                " WHERE excluded.cc_full != ''",
                [row for _line, row in unique.values()],
            )
            inserted = len(novos)

        if self._log is not None:
            marcadas: list[tuple[str, tuple[str, ...]]] = []
            for line, row, expired in batch:
                extra = (MARK_EXPIRED,) if expired else ()
                if row is None:
                    marcadas.append((line, (MARK_INVALID,)))
                elif row[0] in novos:
                    # Só a primeira ocorrência do lote é a que entrou.
                    novos.discard(row[0])
                    marcadas.append((line, (MARK_NEW, *extra)))
                else:
                    marcadas.append((line, (MARK_KNOWN, *extra)))
            self._log.append_many(marcadas, now=moment)

        return inserted, len(validas) - inserted

    def _existing_fingerprints(self, fingerprints: list[str]) -> set[str]:
        encontrados: set[str] = set()
        for start in range(0, len(fingerprints), 500):
            bloco = fingerprints[start : start + 500]
            marcadores = ",".join("?" * len(bloco))
            rows = self._conn.execute(
                f"SELECT fingerprint FROM entries WHERE fingerprint IN ({marcadores})", bloco
            ).fetchall()
            encontrados.update(row["fingerprint"] for row in rows)
        return encontrados
