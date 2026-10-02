"""Consulta de BIN (6 primeiros dígitos) num serviço externo, sempre pelo servidor.

A API key fica só aqui (variável de ambiente); o navegador nunca a vê.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from antiretest.core import InvalidNumberError, parse_entry

API_URL_ENV = "BIN_API_URL"
API_KEY_ENV = "BIN_API_KEY"
DEFAULT_API_URL = "https://tools.nexxuscarding.com/api/bin-checker/bin"

# Cada BIN distinto gasta uma chamada da nossa cota: limita o lote por envio.
MAX_LINHAS = 10_000
MAX_BINS = 2_000
_TIMEOUT = 10
_WORKERS = int(os.environ.get("BIN_API_WORKERS", "8"))


class BinConfigError(RuntimeError):
    """Serviço de BIN sem chave configurada ou recusando a chave."""


def _api_url() -> str:
    return os.environ.get(API_URL_ENV, "").strip() or DEFAULT_API_URL


def _api_key() -> str:
    return os.environ.get(API_KEY_ENV, "").strip()


def configurado() -> bool:
    return bool(_api_key())


def extrair_bin(linha: str) -> str | None:
    """BIN (6 primeiros dígitos do PAN) de uma linha completa e válida.

    Exige número|mês|ano|cvv e número que passe no Luhn; só o BIN (6 dígitos)
    ou um número que não passa no Luhn conta como inválido.
    """
    try:
        return parse_entry(str(linha)).pan[:6]
    except InvalidNumberError:
        return None


def _consultar_um(bin6: str) -> dict[str, Any]:
    url = f"{_api_url()}?{urllib.parse.urlencode({'bin': bin6})}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("X-API-Key", _api_key())
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "AntiReteste (https://antiretest.com, 2.0)")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            corpo = json.loads(resp.read().decode("utf-8") or "{}")
        dados = corpo.get("data") or {}
        return {
            "situacao": "encontrado",
            "bandeira": dados.get("scheme") or "",
            "tipo": dados.get("card_type") or "",
            "banco": dados.get("bank") or "",
            "produto": dados.get("product") or "",
            "pais": dados.get("country") or "",
        }
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return {"situacao": "nao_encontrado"}
        if err.code == 401:
            raise BinConfigError("API key do BIN Checker ausente ou inválida.") from err
        return {"situacao": "erro", "motivo": f"Serviço respondeu {err.code}"}
    except Exception:
        return {"situacao": "erro", "motivo": "Sem resposta do serviço de BIN"}


def consultar_lote(linhas: list[str]) -> dict[str, Any]:
    """Uma chamada por BIN distinto; cada linha aponta para o resultado do seu BIN."""
    if not configurado():
        raise BinConfigError("BIN Checker sem API key configurada no servidor.")

    uteis = [(i + 1, str(ln).strip()) for i, ln in enumerate(linhas) if str(ln).strip()]
    if len(uteis) > MAX_LINHAS:
        raise ValueError(f"Envie no máximo {MAX_LINHAS:,} linhas por vez.".replace(",", "."))

    por_linha = [(numero, bruto, extrair_bin(bruto)) for numero, bruto in uteis]
    distintos = sorted({b for _, _, b in por_linha if b})
    if len(distintos) > MAX_BINS:
        raise ValueError(f"Envie no máximo {MAX_BINS:,} BINs diferentes por vez.".replace(",", "."))

    cache: dict[str, dict[str, Any]] = {}
    if distintos:
        with ThreadPoolExecutor(max_workers=max(1, _WORKERS)) as pool:
            for bin6, res in zip(distintos, pool.map(_consultar_um, distintos)):
                cache[bin6] = res

    itens: list[dict[str, Any]] = []
    resumo = {"encontrado": 0, "nao_encontrado": 0, "invalido": 0, "erro": 0}
    for numero, bruto, bin6 in por_linha:
        if not bin6:
            resumo["invalido"] += 1
            itens.append({"linha": numero, "situacao": "invalido", "bin": None, "cartao": bruto})
            continue
        res = dict(cache.get(bin6, {"situacao": "erro"}))
        res["linha"] = numero
        res["bin"] = bin6
        res["cartao"] = bruto
        resumo[res["situacao"]] = resumo.get(res["situacao"], 0) + 1
        itens.append(res)

    return {"itens": itens, "resumo": resumo, "total": len(por_linha)}
