"""Registro diário em texto: um .txt por dia com tudo que passou pela verificação.

Separado do banco de propósito: o SQLite guarda só fingerprint, BIN e últimos 4,
enquanto esta pasta guarda a linha completa, em claro, com a marca do que
aconteceu com ela (``NOVO``, ``REPETIDO`` ou ``INVALIDO``).
"""

from __future__ import annotations

import os
import re
from datetime import date, datetime, tzinfo
from pathlib import Path
from typing import Iterable

DEFAULT_LOG_DIR_NAME = "registros"
DEFAULT_LOG_DIR = Path(DEFAULT_LOG_DIR_NAME)

MARK_NEW = "NOVO"
MARK_KNOWN = "REPETIDO"
MARK_INVALID = "INVALIDO"
MARK_EXPIRED = "VENCIDO"
MARKS = (MARK_NEW, MARK_KNOWN, MARK_INVALID, MARK_EXPIRED)

# As marcas entram como campos extras no fim da linha (``...|NOVO|VENCIDO``).
# Campos extras são descartados na leitura, então o txt continua reimportável.
MARK_SEPARATOR = "|"

_QUEBRAS = re.compile(r"[\r\n]+")


def default_log_dir(db_path: str | Path) -> Path:
    """Pasta ``registros/`` ao lado do banco, para os dois andarem juntos."""
    parent = Path(db_path).expanduser().absolute().parent
    return parent / DEFAULT_LOG_DIR_NAME


def log_zone() -> tzinfo | None:
    """Fuso do corte do dia: ``ANTIRETEST_TZ`` ou o fuso do sistema (None).

    A variável existe para o lado PHP poder combinar com este: lá o fuso do
    próprio PHP costuma vir errado (herdado do php.ini).
    """
    nome = os.environ.get("ANTIRETEST_TZ")
    if not nome:
        return None
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(nome)
    except Exception:  # sem tzdata ou nome inválido: fica o fuso do sistema
        return None


def _as_marks(marks: Iterable[str] | str | None) -> tuple[str, ...]:
    """Aceita uma marca só, várias, ou nenhuma."""
    if marks is None:
        return ()
    if isinstance(marks, str):
        return (marks,)
    return tuple(marca for marca in marks if marca)


def _today(now: datetime | None) -> date:
    """Data do arquivo, em horário local: vira à meia-noite de quem usa."""
    return (now or datetime.now()).astimezone(log_zone()).date()


def split_marks(line: str) -> tuple[str, tuple[str, ...]]:
    """Separa a linha das marcas no fim; tupla vazia quando não houver."""
    restante = line
    marcas: list[str] = []
    while True:
        prefixo, separador, sufixo = restante.rpartition(MARK_SEPARATOR)
        if not separador or sufixo.strip() not in MARKS:
            return restante, tuple(reversed(marcas))
        marcas.append(sufixo.strip())
        restante = prefixo


class DailyLog:
    """Acumula num arquivo por dia (``registros/AAAA-MM-DD.txt``) o que foi verificado.

    Cada linha entra como veio (``PAN|MM|AAAA|CVV`` inclusive), seguida das
    marcas, uma por linha do arquivo. O txt do dia pode ser relido direto por
    ``antiretest import registros/AAAA-MM-DD.txt``.
    """

    def __init__(self, directory: str | Path = DEFAULT_LOG_DIR) -> None:
        self.directory = Path(directory)

    def path_for(self, day: date) -> Path:
        return self.directory / f"{day.isoformat()}.txt"

    def append(self, line: str, *marks: str, now: datetime | None = None) -> Path:
        """Grava uma linha no txt de hoje e devolve o arquivo usado."""
        return self.append_many([(line, marks)], now=now)

    def append_many(
        self,
        entries: Iterable[tuple[str, Iterable[str] | str | None]],
        *,
        now: datetime | None = None,
    ) -> Path:
        """Grava vários pares (linha, marcas), abrindo o arquivo uma única vez."""
        path = self.path_for(_today(now))
        conteudo = []
        for line, marks in entries:
            # Uma entrada nunca pode virar duas linhas no txt: quebras viram espaço.
            texto = _QUEBRAS.sub(" ", str(line)).strip()
            if not texto:
                continue
            for marca in _as_marks(marks):
                texto += f"{MARK_SEPARATOR}{marca}"
            conteudo.append(f"{texto}\n")
        if not conteudo:
            return path
        self.directory.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.writelines(conteudo)
        return path

    def numbers_for(self, day: date) -> list[str]:
        """Linhas gravadas num dia, com as marcas, na ordem em que entraram."""
        path = self.path_for(day)
        if not path.is_file():
            return []
        with path.open(encoding="utf-8-sig", errors="replace") as handle:
            return [linha.strip() for linha in handle if linha.strip()]

    def entries_for(self, day: date) -> list[tuple[str, tuple[str, ...]]]:
        """Mesmo conteúdo de ``numbers_for``, com as marcas já separadas."""
        return [split_marks(linha) for linha in self.numbers_for(day)]

    def days(self) -> list[date]:
        """Dias que já têm arquivo, do mais antigo para o mais recente."""
        if not self.directory.is_dir():
            return []
        dias = []
        for path in self.directory.glob("*.txt"):
            try:
                dias.append(date.fromisoformat(path.stem))
            except ValueError:  # arquivo que não segue o padrão de data
                continue
        return sorted(dias)

    def counts(self) -> list[tuple[date, int]]:
        """(dia, quantidade de linhas) para cada arquivo da pasta."""
        return [(dia, len(self.numbers_for(dia))) for dia in self.days()]

    def tally(self, day: date) -> dict[str, int]:
        """Quantas linhas de cada marca num dia."""
        resumo = {marca: 0 for marca in MARKS}
        resumo["total"] = 0
        for _linha, marcas in self.entries_for(day):
            resumo["total"] += 1
            for marca in marcas:
                resumo[marca] += 1
        return resumo
