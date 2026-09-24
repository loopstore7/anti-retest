"""API e frontend do Anti Reteste V2."""

from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from antiretest.core import mask_vulgo, sanitize_vulgo
from antiretest.engine_pg import AntiRetestPg

from .schemas import CheckItem, CheckRequest, CheckResponse, StatsResponse

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
STATIC_DIR = Path(__file__).parent / "static"

engine: AntiRetestPg | None = None

SITUACOES = {
    "novo": {"rotulo": "Novo", "tom": "ok"},
    "existente": {"rotulo": "Existente", "tom": "ambar"},
    "repetido": {"rotulo": "Repetido", "tom": "indigo"},
    "invalido": {"rotulo": "Inválido", "tom": "erro"},
}

MESES = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"]


def data_curta(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(str(iso)[:10])
    except ValueError:
        return "—"
    return f"{dt.day} {MESES[dt.month - 1]} {dt.year}"


def n(valor: int | float | None) -> str:
    return f"{int(valor or 0):,}".replace(",", ".")


def motivo_curto(motivo: str) -> tuple[str, str]:
    m = motivo.lower()
    if "validade" in m or "cvv" in m:
        return "Linha incompleta", "Falta validade ou CVV"
    if "nenhum" in m:
        return "Linha vazia", "Nenhum número encontrado"
    if "luhn" in m or "dígito" in m or "cartão" in m:
        return "Número inválido", "PAN ou Luhn incorreto"
    return "Linha inválida", "Formato não reconhecido"


def build_registros(resultado: dict[str, Any]) -> list[dict[str, Any]]:
    registros: list[dict[str, Any]] = []
    for item in resultado["new"]:
        registros.append({
            "linha": item["line"],
            "numero": item["masked"],
            "motivo": None,
            "situacao": "novo",
            "registro": None,
            "registro_nota": None,
            "consultas": item["attempts"],
            "vulgo": item.get("vulgo", ""),
            "cc_full": item.get("cc_full", ""),
        })
    for item in resultado["known"]:
        dias = int(item["days_since_added"])
        registros.append({
            "linha": item["line"],
            "numero": item["masked"],
            "motivo": None,
            "situacao": "existente",
            "registro": data_curta(item["added_on"]),
            "registro_nota": "Registrado hoje" if dias == 0 else f"Registrado há {dias} dia(s)",
            "consultas": item["attempts"],
            "vulgo": item.get("vulgo", ""),
            "cc_full": item.get("cc_full", ""),
        })
    for item in resultado["duplicated"]:
        registros.append({
            "linha": item["line"],
            "numero": item["masked"],
            "motivo": None,
            "situacao": "repetido",
            "registro": f"Linha {item['first_line']}",
            "registro_nota": "Duplicado no lote",
            "consultas": None,
            "vulgo": item.get("vulgo", ""),
            "cc_full": item.get("cc_full", ""),
        })
    for item in resultado["invalid"]:
        registros.append({
            "linha": item["line"],
            "numero": None,
            "motivo": item["reason"],
            "situacao": "invalido",
            "registro": None,
            "registro_nota": None,
            "consultas": None,
            "vulgo": None,
            "cc_full": "",
        })
    registros.sort(key=lambda r: r["linha"])
    return registros


def build_api_response(resultado: dict[str, Any]) -> CheckResponse:
    items: list[CheckItem] = []
    for item in resultado["new"]:
        items.append(CheckItem(
            line=int(item["line"]),
            status="new",
            masked=item.get("masked"),
            cc_full=item.get("cc_full", ""),
            fingerprint=item.get("fingerprint"),
            is_retest=bool(item.get("is_retest")),
            added_on=item.get("added_on"),
            days_since_added=int(item.get("days_since_added", 0)),
            attempts=int(item.get("attempts", 1)),
            expiry=item.get("expiry"),
            expired=bool(item.get("expired")),
            vulgo=item.get("vulgo"),
        ))
    for item in resultado["known"]:
        items.append(CheckItem(
            line=int(item["line"]),
            status="known",
            masked=item.get("masked"),
            cc_full=item.get("cc_full", ""),
            fingerprint=item.get("fingerprint"),
            is_retest=True,
            added_on=item.get("added_on"),
            days_since_added=int(item.get("days_since_added", 0)),
            attempts=int(item.get("attempts", 0)),
            expiry=item.get("expiry"),
            expired=bool(item.get("expired")),
            vulgo=mask_vulgo(item.get("vulgo") or "") or item.get("vulgo"),
        ))
    for item in resultado["duplicated"]:
        items.append(CheckItem(
            line=int(item["line"]),
            status="duplicated",
            masked=item.get("masked"),
            cc_full=item.get("cc_full", ""),
            first_line=int(item.get("first_line", 0)),
            vulgo=mask_vulgo(item.get("vulgo") or "") or item.get("vulgo"),
        ))
    for item in resultado["invalid"]:
        items.append(CheckItem(
            line=int(item["line"]),
            status="invalid",
            reason=item.get("reason"),
        ))
    items.sort(key=lambda i: i.line)
    return CheckResponse(
        total=int(resultado["total"]),
        new=len(resultado["new"]),
        known=len(resultado["known"]),
        duplicated=len(resultado["duplicated"]),
        invalid=len(resultado["invalid"]),
        items=items,
    )


def _base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


def _page_ctx(request: Request, **extra: Any) -> dict[str, Any]:
    ctx = {
        "aba_ativa": extra.pop("aba_ativa", "verificacao"),
        "base_url": _base_url(request),
        "n": n,
        "data_curta": data_curta,
        "motivo_curto": motivo_curto,
        "mask_vulgo": mask_vulgo,
    }
    ctx.update(extra)
    return ctx


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global engine
    engine = AntiRetestPg()
    yield
    if engine:
        engine.close()
        engine = None


app = FastAPI(
    title="Anti Reteste V2",
    description="API de verificação anti-reteste — consulte cartões e detecte repetições.",
    version="2.0.0",
    lifespan=lifespan,
)
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", secrets.token_hex(32)))
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/stats", response_model=StatsResponse)
def api_stats() -> StatsResponse:
    assert engine is not None
    raw = engine.stats()
    return StatsResponse(
        total=int(raw["total"]),
        attempts=int(raw["attempts"]),
        repetidos=int(raw["repetidos"]),
        retested=int(raw["retested"]),
        first_day=str(raw["first_day"]) if raw.get("first_day") else None,
        last_day=str(raw["last_day"]) if raw.get("last_day") else None,
    )


@app.post("/api/check", response_model=CheckResponse)
def api_check(body: CheckRequest) -> CheckResponse:
    assert engine is not None
    vulgo = sanitize_vulgo(body.vulgo)
    if not vulgo:
        raise HTTPException(status_code=400, detail="vulgo obrigatório")
    lines = [ln.strip() for ln in body.lines if str(ln).strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="lines não pode ser vazio")
    resultado = engine.check_many(lines, record_new=body.record, vulgo=vulgo)
    return build_api_response(resultado)


@app.get("/documentacao", response_class=HTMLResponse)
async def documentacao(request: Request) -> HTMLResponse:
    assert engine is not None
    try:
        stats = engine.stats()
    except Exception:
        stats = None
    return TEMPLATES.TemplateResponse(
        request,
        "documentacao.html",
        _page_ctx(request, aba_ativa="documentacao", stats=stats),
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    assert engine is not None
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_hex(16)
    try:
        stats = engine.stats()
        erro = None
    except Exception as exc:
        stats = None
        erro = f"Falha ao abrir o banco: {exc}"
    agora = datetime.now(timezone.utc)
    return TEMPLATES.TemplateResponse(
        request,
        "index.html",
        _page_ctx(
            request,
            aba_ativa="verificacao",
            csrf=request.session["csrf"],
            stats=stats,
            erro=erro,
            entrada="",
            vulgo="",
            registros=[],
            resultado=None,
            situacoes=SITUACOES,
            agora_hora=agora.strftime("%H:%M"),
            exibe_consultas=int(stats["attempts"]) if stats else 0,
            exibe_repetidos=int(stats["repetidos"]) if stats else 0,
            nota_ultimo=data_curta(stats["last_day"]) if stats and stats.get("last_day") else "—",
        ),
    )


@app.post("/", response_class=HTMLResponse)
async def verify(
    request: Request,
    csrf: str = Form(""),
    vulgo: str = Form(""),
    numeros: str = Form(""),
) -> HTMLResponse:
    assert engine is not None
    if csrf != request.session.get("csrf"):
        raise HTTPException(status_code=400, detail="Sessão expirada")
    entrada = numeros
    erro = None
    resultado = None
    registros: list[dict[str, Any]] = []
    vulgo = vulgo.strip()
    if not vulgo:
        erro = "Informe a Store (ou vulgo) antes de verificar."
    else:
        linhas = [ln.strip() for ln in numeros.splitlines()]
        try:
            resultado = engine.check_many(linhas, record_new=True, vulgo=vulgo)
            registros = build_registros(resultado)
        except Exception as exc:
            erro = f"Falha ao acessar o banco: {exc}"
    try:
        stats = engine.stats()
    except Exception as exc:
        stats = None
        erro = erro or f"Falha ao abrir o banco: {exc}"
    agora = datetime.now(timezone.utc)
    return TEMPLATES.TemplateResponse(
        request,
        "index.html",
        _page_ctx(
            request,
            aba_ativa="verificacao",
            csrf=request.session.get("csrf", ""),
            stats=stats,
            erro=erro,
            entrada=entrada,
            vulgo=vulgo,
            registros=registros,
            resultado=resultado,
            situacoes=SITUACOES,
            agora_hora=agora.strftime("%H:%M"),
            exibe_consultas=int(stats["attempts"]) if stats else 0,
            exibe_repetidos=int(stats["repetidos"]) if stats else 0,
            nota_ultimo=data_curta(stats["last_day"]) if stats and stats.get("last_day") else "—",
        ),
    )
