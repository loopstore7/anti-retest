"""Testes do BIN Checker: extração de BIN, consulta em lote e rota HTTP."""

from __future__ import annotations

import os
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# engine_pg importa psycopg no topo; aqui ele não é usado.
if "psycopg" not in sys.modules:
    psycopg = types.ModuleType("psycopg")
    rows = types.ModuleType("psycopg.rows")
    rows.dict_row = None
    psycopg.rows = rows
    pool = types.ModuleType("psycopg_pool")
    pool.ConnectionPool = object
    sys.modules.update({"psycopg": psycopg, "psycopg.rows": rows, "psycopg_pool": pool})

from backend.app import bin_checker  # noqa: E402
from backend.app.registro_externo import _linha_bin, _linhas_envio  # noqa: E402


class LinhaAnexoDiscord(unittest.TestCase):
    def test_encontrado_vem_com_dados(self):
        item = {
            "cartao": "5201328403768238|09|28|544", "situacao": "encontrado", "bin": "520132",
            "bandeira": "MASTERCARD", "tipo": "CREDIT", "banco": "BANCO SANTANDER (BRASIL) S.A.",
            "produto": "PLATINUM", "pais": "Brazil",
        }
        self.assertEqual(
            _linha_bin(item),
            "5201328403768238|09|28|544 520132\tMASTERCARD\tCREDIT\tBANCO SANTANDER (BRASIL) S.A.\tPLATINUM\tBrazil",
        )

    def test_invalido(self):
        self.assertEqual(_linha_bin({"cartao": "553636", "situacao": "invalido", "bin": None}), "553636\tINVÁLIDO")


class LinhaAnexoEnvio(unittest.TestCase):
    def test_status_por_linha(self):
        lines = [
            "5555555555554444|01|2035|000|Bruno",
            "",
            "4111111111111111|12|2028|123",
            "5555555555554444|01|2035|000",
            "lixo",
        ]
        resultado = {
            "new": [{"line": 1}],
            "known": [{"line": 3, "added_on": "2026-09-27"}],
            "duplicated": [{"line": 4, "first_line": 1}],
            "invalid": [{"line": 5, "reason": "x"}],
        }
        self.assertEqual(_linhas_envio(lines, resultado), [
            "5555555555554444|01|2035|000|Bruno\tNOVO",
            "4111111111111111|12|2028|123\tJÁ EXISTE (desde 27/09/2026)",
            "5555555555554444|01|2035|000\tREPETIDO NO LOTE (linha 1)",
            "lixo\tINVÁLIDO",
        ])


class ExtrairBin(unittest.TestCase):
    def test_linha_completa_usa_6_primeiros(self):
        self.assertEqual(bin_checker.extrair_bin("5555 5555 5555 4444|01|2035|000"), "555555")

    def test_so_bin_6_digitos_e_invalido(self):
        # Sem validade/CVV não é linha completa.
        self.assertIsNone(bin_checker.extrair_bin("553636"))

    def test_numero_que_falha_luhn_e_invalido(self):
        self.assertIsNone(bin_checker.extrair_bin("5555555555554445|01|2035|000"))

    def test_lixo_e_invalido(self):
        self.assertIsNone(bin_checker.extrair_bin("abc12"))
        self.assertIsNone(bin_checker.extrair_bin(""))


class ConsultarLote(unittest.TestCase):
    def setUp(self):
        os.environ["BIN_API_KEY"] = "chave-teste"
        self._orig = bin_checker._consultar_um

        def falso(bin6: str):
            if bin6 == "555555":
                return {"situacao": "encontrado", "bandeira": "MASTERCARD", "tipo": "CREDIT",
                        "banco": "BANCO DO BRASIL S.A.", "produto": "MASTERCARD STANDARD", "pais": "BR"}
            return {"situacao": "nao_encontrado"}

        bin_checker._consultar_um = falso

    def tearDown(self):
        bin_checker._consultar_um = self._orig
        os.environ.pop("BIN_API_KEY", None)

    def test_dedup_e_resumo(self):
        linhas = [
            "5555555555554444|01|2035|000",  # BIN 555555 -> encontrado
            "5555555555554444|05|2030|111",  # mesmo BIN -> 1 só chamada, encontrado
            "4111111111111111|12|2028|123",  # BIN 411111 -> não encontrado
            "553636",                        # só 6 dígitos -> inválido
        ]
        res = bin_checker.consultar_lote(linhas)
        self.assertEqual(res["total"], 4)
        self.assertEqual(res["resumo"]["encontrado"], 2)
        self.assertEqual(res["resumo"]["nao_encontrado"], 1)
        self.assertEqual(res["resumo"]["invalido"], 1)
        por_linha = {it["linha"]: it for it in res["itens"]}
        self.assertEqual(por_linha[1]["bandeira"], "MASTERCARD")
        self.assertEqual(por_linha[1]["cartao"], "5555555555554444|01|2035|000")
        # A linha volta exatamente como o cliente enviou, com nome/CPF e demais campos.
        extra = bin_checker.consultar_lote(["5555555555554444|2|2030|071|Bruno|123456"])
        self.assertEqual(extra["itens"][0]["cartao"], "5555555555554444|2|2030|071|Bruno|123456")
        self.assertEqual(extra["itens"][0]["bin"], "555555")
        self.assertEqual(por_linha[4]["situacao"], "invalido")
        self.assertEqual(por_linha[4]["cartao"], "553636")
        self.assertIsNone(por_linha[4]["bin"])

    def test_sem_chave_levanta(self):
        os.environ.pop("BIN_API_KEY", None)
        with self.assertRaises(bin_checker.BinConfigError):
            bin_checker.consultar_lote(["5555555555554444|01|2035|000"])


if __name__ == "__main__":
    unittest.main()
