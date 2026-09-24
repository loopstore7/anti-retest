#!/usr/bin/env python3
"""Troca a chave dos registros: de só o número para o cartão inteiro (número|mês|ano|cvv).

Depois disso, o mesmo número com mês, ano ou CVV diferente conta como NOVO.
Registros sem cc_full ficam com a chave antiga e nunca mais batem com um cartão.
Pode rodar mais de uma vez: quem já está na chave nova é pulado.
"""

from __future__ import annotations

import os
import sys
import time

import psycopg
from psycopg.rows import dict_row

from antiretest.core import InvalidNumberError, format_cc_full_from_entry, parse_entry
from antiretest.engine_pg import FP_SCHEME, PG_SCHEMA, card_fingerprint

BATCH = int(os.environ.get("MIGRATE_BATCH", "10000"))


def resolve_key(conn: psycopg.Connection) -> bytes:
    from_env = os.environ.get("ANTIRETEST_KEY")
    if from_env:
        return from_env.encode("utf-8")
    row = conn.execute("SELECT value FROM meta WHERE key = 'key'").fetchone()
    if not row:
        raise SystemExit("Chave HMAC não encontrada (meta.key ou ANTIRETEST_KEY).")
    return bytes.fromhex(row["value"])


def rekey(conn: psycopg.Connection, pares: list[tuple[str, str]]) -> tuple[int, int]:
    """Aplica (antigo, novo); se o novo já existir, soma as consultas nele e apaga o antigo."""
    existentes = {
        r["fingerprint"]
        for r in conn.execute(
            "SELECT fingerprint FROM entries WHERE fingerprint = ANY(%s)",
            ([novo for _, novo in pares],),
        )
    }
    trocas = [(novo, antigo) for antigo, novo in pares if novo not in existentes]
    fusoes = [(antigo, novo) for antigo, novo in pares if novo in existentes]
    with conn.cursor() as cur:
        if trocas:
            cur.executemany("UPDATE entries SET fingerprint = %s WHERE fingerprint = %s", trocas)
        for antigo, novo in fusoes:
            cur.execute(
                "UPDATE entries AS n SET"
                " attempts = n.attempts + o.attempts,"
                " added_at = LEAST(n.added_at, o.added_at),"
                " added_on = LEAST(n.added_on, o.added_on),"
                " last_seen_at = GREATEST(n.last_seen_at, o.last_seen_at)"
                " FROM entries AS o WHERE n.fingerprint = %s AND o.fingerprint = %s",
                (novo, antigo),
            )
            cur.execute("DELETE FROM entries WHERE fingerprint = %s", (antigo,))
    return len(trocas), len(fusoes)


def main() -> int:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL obrigatório", file=sys.stderr)
        return 2

    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute(PG_SCHEMA)
        key = resolve_key(conn)
        total = conn.execute("SELECT COUNT(*) AS n FROM entries").fetchone()["n"]
        print(f"verificando {total:,} registros (lote {BATCH})...".replace(",", "."))

        t0 = time.time()
        lidos = trocados = fundidos = sem_cartao = 0
        pendentes: list[tuple[str, str]] = []
        with conn.cursor(name="rekey", row_factory=dict_row) as leitura:
            leitura.itersize = BATCH
            leitura.execute("SELECT fingerprint, cc_full FROM entries")
            for row in leitura:
                lidos += 1
                try:
                    entry = parse_entry(str(row["cc_full"] or "").strip())
                except InvalidNumberError:
                    sem_cartao += 1
                    continue
                novo = card_fingerprint(format_cc_full_from_entry(entry), key)
                if novo != row["fingerprint"]:
                    pendentes.append((row["fingerprint"], novo))
                if len(pendentes) >= BATCH:
                    t, f = rekey(conn, pendentes)
                    trocados, fundidos, pendentes = trocados + t, fundidos + f, []
                    rate = lidos / max(time.time() - t0, 0.001)
                    print(f"  {lidos:,}/{total:,} ({rate:,.0f}/s)".replace(",", "."))
        if pendentes:
            t, f = rekey(conn, pendentes)
            trocados, fundidos = trocados + t, fundidos + f

        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('fp_scheme', %s)"
            " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (FP_SCHEME,),
        )
        conn.commit()

    print(
        f"concluído: trocados={trocados:,} fundidos={fundidos:,}"
        f" sem_cartao_completo={sem_cartao:,}".replace(",", ".")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
