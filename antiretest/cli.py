"""Interface de linha de comando do anti-retest."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from .core import DEFAULT_DB_PATH, DEFAULT_SEED_PATH, AntiRetest, InvalidNumberError
from .daily_log import (
    MARK_EXPIRED,
    MARK_INVALID,
    MARK_KNOWN,
    MARK_NEW,
    DailyLog,
    default_log_dir,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antiretest",
        description=(
            "Verifica cartões e mostra em que dia entraram no banco."
            " Exige a linha completa PAN|MM|AAAA|CVV: 16 dígitos (ou 15 na Amex),"
            " validade e CVV de 3 dígitos (4 na Amex)."
        ),
    )
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="caminho do banco SQLite")
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    parser.add_argument(
        "--log-dir",
        help="pasta dos txt diários (padrão: registros/ ao lado do banco)",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="não gravar o txt diário com as linhas verificadas",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check",
        help="consulta cartões completos, PAN|MM|AAAA|CVV (use - para ler do stdin)",
    )
    check.add_argument("numbers", nargs="+")
    check.add_argument(
        "--dry-run",
        action="store_true",
        help="consulta sem gravar a tentativa",
    )

    forget = sub.add_parser("forget", help="remove números do histórico")
    forget.add_argument("numbers", nargs="+")

    purge = sub.add_parser("purge", help="apaga registros antigos")
    purge.add_argument("days", type=int, help="remover registros com mais de N dias")

    sub.add_parser("stats", help="resumo do banco")

    log_cmd = sub.add_parser("log", help="lista os txt diários (ou os números de um dia)")
    log_cmd.add_argument("day", nargs="?", help="dia a listar, no formato AAAA-MM-DD")

    sub.add_parser("gui", help="abre a interface gráfica")

    web = sub.add_parser("web", help="abre a interface no navegador (localhost)")
    web.add_argument("--host", default="127.0.0.1", help="interface de escuta")
    web.add_argument("--port", type=int, default=8000, help="porta (0 escolhe uma livre)")
    web.add_argument(
        "--no-browser",
        action="store_true",
        help="não abrir o navegador automaticamente",
    )

    import_cmd = sub.add_parser(
        "import",
        help="importa números de um arquivo texto (padrão: db.txt)",
    )
    import_cmd.add_argument(
        "file",
        nargs="?",
        default=str(DEFAULT_SEED_PATH),
        help="arquivo com um número por linha",
    )
    import_cmd.add_argument(
        "--batch-size",
        type=int,
        default=5000,
        help="tamanho do lote de gravação no SQLite",
    )
    return parser


def _collect(numbers: list[str]) -> list[str]:
    if numbers == ["-"]:
        return [line.strip() for line in sys.stdin if line.strip()]
    return numbers


def _log_dir(args: argparse.Namespace) -> Path:
    return Path(args.log_dir) if args.log_dir else default_log_dir(args.db)


def _log_command(args: argparse.Namespace) -> int:
    diario = DailyLog(_log_dir(args))

    if args.day:
        try:
            dia = date.fromisoformat(args.day)
        except ValueError:
            print(f"data inválida: {args.day} (use AAAA-MM-DD)", file=sys.stderr)
            return 2
        linhas = diario.numbers_for(dia)
        if args.json:
            print(
                json.dumps(
                    {
                        "day": dia.isoformat(),
                        "file": str(diario.path_for(dia)),
                        "lines": [
                            {"line": linha, "marks": list(marcas)}
                            for linha, marcas in diario.entries_for(dia)
                        ],
                        "tally": diario.tally(dia),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            for linha in linhas:
                print(linha)
            print(f"{_resumo(diario, dia)} em {diario.path_for(dia)}", file=sys.stderr)
        return 0

    dias = diario.days()
    if args.json:
        print(
            json.dumps(
                [{"day": dia.isoformat(), **diario.tally(dia)} for dia in dias],
                ensure_ascii=False,
                indent=2,
            )
        )
    elif dias:
        for dia in dias:
            print(f"{dia.isoformat()}: {_resumo(diario, dia)}")
    else:
        print(f"nenhum txt em {diario.directory}")
    return 0


def _resumo(diario: DailyLog, dia: date) -> str:
    resumo = diario.tally(dia)
    return (
        f"{resumo['total']} linha(s) · {resumo[MARK_NEW]} novo(s),"
        f" {resumo[MARK_KNOWN]} repetido(s), {resumo[MARK_INVALID]} inválido(s),"
        f" {resumo[MARK_EXPIRED]} vencido(s)"
    )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    exit_code = 0

    if args.command == "log":
        return _log_command(args)

    log_dir = None if args.no_log else _log_dir(args)

    if args.command == "gui":
        from .gui import run

        run(args.db, log_dir=log_dir)
        return 0

    if args.command == "web":
        from .web import run as run_web

        run_web(
            args.db,
            host=args.host,
            port=args.port,
            open_browser=not args.no_browser,
            log_dir=log_dir,
        )
        return 0

    with AntiRetest(args.db, log_dir=log_dir) as engine:
        if args.command == "check":
            payload = []
            for number in _collect(args.numbers):
                try:
                    result = engine.check(number, record=not args.dry_run)
                except InvalidNumberError as error:
                    exit_code = max(exit_code, 2)
                    if args.json:
                        payload.append({"input": number, "error": str(error)})
                    else:
                        print(f"{number}: INVÁLIDO — {error}", file=sys.stderr)
                    continue

                if result.is_retest:
                    exit_code = max(exit_code, 1)
                if args.json:
                    payload.append(
                        {
                            "masked": result.masked,
                            "fingerprint": result.fingerprint,
                            "status": result.status,
                            "added_on": result.added_on.isoformat(),
                            "days_since_added": result.days_since_added,
                            "attempts": result.attempts,
                            "expiry": result.expiry,
                            "expired": result.expired,
                        }
                    )
                else:
                    print(result.describe())
            if args.json:
                print(json.dumps(payload, ensure_ascii=False, indent=2))

        elif args.command == "forget":
            removed = 0
            for number in _collect(args.numbers):
                try:
                    removed += int(engine.forget(number))
                except InvalidNumberError as error:
                    exit_code = max(exit_code, 2)
                    print(f"{number}: INVÁLIDO — {error}", file=sys.stderr)
            print(f"{removed} registro(s) removido(s)")

        elif args.command == "purge":
            print(f"{engine.purge(args.days)} registro(s) removido(s)")

        elif args.command == "stats":
            stats = engine.stats()
            if args.json:
                print(json.dumps(stats, ensure_ascii=False, indent=2))
            else:
                for key, value in stats.items():
                    print(f"{key}: {value}")

        elif args.command == "import":
            seed = Path(args.file)
            if not seed.is_file():
                print(f"arquivo não encontrado: {seed}", file=sys.stderr)
                return 2
            engine._conn.execute("PRAGMA journal_mode=WAL")
            engine._conn.execute("PRAGMA synchronous=NORMAL")
            print(f"importando de {seed}...", file=sys.stderr)
            result = engine.import_file(seed, batch_size=args.batch_size)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(
                    f"{result['imported']} importado(s) · "
                    f"{result['duplicates']} duplicado(s) · "
                    f"{result['invalid']} inválido(s) · "
                    f"{result['expired']} vencido(s) · "
                    f"{result['lines']} linha(s) lida(s)"
                )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
