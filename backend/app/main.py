"""API e frontend do Anti Reteste V2."""

from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from starlette.middleware.sessions import SessionMiddleware

from antiretest.core import mask_vulgo, sanitize_vulgo
from antiretest.engine_pg import AntiRetestPg

from .schemas import CheckItem, CheckRequest, CheckResponse, StatsResponse, VerificarRequest

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
STATIC_DIR = Path(__file__).parent / "static"

engine: AntiRetestPg | None = None

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


def marca_svg(tamanho: int) -> Markup:
    return Markup(
        f'<svg class="marca-sim" width="{tamanho}" height="{tamanho}" viewBox="0 0 20 20"'
        ' fill="none" aria-hidden="true">'
        '<rect x="3.2" y="3.2" width="13.6" height="13.6" rx="3" transform="rotate(45 10 10)"'
        ' stroke="currentColor" stroke-width="1.4" opacity=".55"/>'
        '<rect x="6.8" y="6.8" width="6.4" height="6.4" rx="1.6" transform="rotate(45 10 10)"'
        ' fill="currentColor"/>'
        "</svg>"
    )


def vulgo_testado_por(vulgo: str | None, situacao: str) -> str | None:
    if situacao not in ("existente", "repetido"):
        return None
    mascarado = mask_vulgo(vulgo or "")
    return mascarado or None


def nota_ultimo_registro(stats: dict[str, Any] | None, agora: datetime) -> str:
    if not stats or not stats.get("last_day"):
        return "—"
    try:
        ultimo = datetime.fromisoformat(str(stats["last_day"])[:10]).replace(tzinfo=timezone.utc)
    except ValueError:
        return "—"
    dias = (agora.date() - ultimo.date()).days
    if dias == 0:
        return "hoje"
    return f"há {n(dias)} dias"


def build_stats_payload(stats: dict[str, Any] | None, agora: datetime) -> dict[str, Any] | None:
    if not stats:
        return None
    return {
        "total": int(stats["total"]),
        "consultas": int(stats["attempts"]),
        "repetidos": int(stats["repetidos"]),
        "ultimo": data_curta(stats.get("last_day")),
        "ultimo_nota": nota_ultimo_registro(stats, agora),
    }


def build_payload(resultado: dict[str, Any], agora: datetime) -> dict[str, Any]:
    """Resultado enxuto para a página montar a tabela no navegador."""
    itens: list[dict[str, Any]] = []
    for reg in build_registros(resultado):
        item: dict[str, Any] = {"linha": reg["linha"], "situacao": reg["situacao"]}
        if reg["numero"]:
            cc_full = (reg.get("cc_full") or "").strip()
            item["numero"] = cc_full or reg["numero"]
            if cc_full:
                item["completo"] = True
        else:
            item["motivo"] = motivo_curto(reg["motivo"] or "")
            item["detalhe"] = reg["motivo"]
        if reg["registro"]:
            item["registro"] = reg["registro"]
            item["nota"] = reg["registro_nota"]
        testado = vulgo_testado_por(reg["vulgo"], reg["situacao"])
        if testado:
            item["testado"] = testado
        if reg["consultas"] is not None:
            item["consultas"] = int(reg["consultas"])
        itens.append(item)
    return {
        "itens": itens,
        "resumo": {
            "novo": len(resultado["new"]),
            "existente": len(resultado["known"]),
            "repetido": len(resultado["duplicated"]),
            "invalido": len(resultado["invalid"]),
        },
        "agora_hora": agora.strftime("%H:%M"),
        "agora_rotulo": f"{data_curta(agora.strftime('%Y-%m-%d'))}, {agora.strftime('%H:%M')} UTC",
    }


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
            "registro_nota": (
                "Registrado hoje" if dias == 0
                else f"Registrado há {n(dias)} {'dia' if dias == 1 else 'dias'}"
            ),
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


def static_url(nome: str) -> str:
    """URL do arquivo estático com a versão embutida: mudou o arquivo, o navegador baixa de novo."""
    try:
        versao = int((STATIC_DIR / nome).stat().st_mtime)
    except OSError:
        return f"/static/{nome}"
    return f"/static/{nome}?v={versao}"


def _page_ctx(request: Request, **extra: Any) -> dict[str, Any]:
    ctx = {
        "aba_ativa": extra.pop("aba_ativa", "verificacao"),
        "base_url": _base_url(request),
        "static_url": static_url,
        "n": n,
        "data_curta": data_curta,
        "marca_svg": marca_svg,
        "erro": extra.get("erro"),
        "exibe_consultas": extra.get("exibe_consultas", 0),
        "exibe_repetidos": extra.get("exibe_repetidos", 0),
    }
    ctx.update(extra)
    return ctx


def _stats_extras(stats: dict[str, Any] | None, agora: datetime) -> dict[str, Any]:
    return {
        "exibe_consultas": int(stats["attempts"]) if stats else 0,
        "exibe_repetidos": int(stats["repetidos"]) if stats else 0,
        "nota_ultimo": nota_ultimo_registro(stats, agora),
        "agora_hora": agora.strftime("%H:%M"),
    }


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
app.add_middleware(GZipMiddleware, minimum_size=1024)
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
def documentacao(request: Request) -> HTMLResponse:
    assert engine is not None
    try:
        stats = engine.stats()
        erro = None
    except Exception as exc:
        stats = None
        erro = f"Falha ao abrir o banco: {exc}"
    agora = datetime.now(timezone.utc)
    return TEMPLATES.TemplateResponse(
        request,
        "documentacao.html",
        _page_ctx(
            request,
            aba_ativa="documentacao",
            stats=stats,
            erro=erro,
            **_stats_extras(stats, agora),
        ),
    )


def _render_index(
    request: Request,
    *,
    entrada: str = "",
    vulgo: str = "",
    resultado: dict[str, Any] | None = None,
    erro: str | None = None,
) -> HTMLResponse:
    assert engine is not None
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_hex(16)
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
            csrf=request.session["csrf"],
            stats=stats,
            erro=erro,
            entrada=entrada,
            vulgo=vulgo,
            payload=build_payload(resultado, agora) if resultado is not None else None,
            **_stats_extras(stats, agora),
        ),
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return _render_index(request)


@app.post("/", response_class=HTMLResponse)
def verify(
    request: Request,
    csrf: str = Form(""),
    vulgo: str = Form(""),
    numeros: str = Form(""),
) -> HTMLResponse:
    assert engine is not None
    if csrf != request.session.get("csrf"):
        raise HTTPException(status_code=400, detail="Sessão expirada")
    vulgo = vulgo.strip()
    if not vulgo:
        return _render_index(request, entrada=numeros, erro="Informe a Store (ou vulgo) antes de verificar.")
    try:
        resultado = engine.check_many(numeros.splitlines(), record_new=True, vulgo=vulgo)
    except Exception as exc:
        return _render_index(request, entrada=numeros, vulgo=vulgo, erro=f"Falha ao acessar o banco: {exc}")
    return _render_index(request, entrada=numeros, vulgo=vulgo, resultado=resultado)


@app.post("/verificar")
def verificar(request: Request, body: VerificarRequest) -> dict[str, Any]:
    assert engine is not None
    if body.csrf != request.session.get("csrf"):
        raise HTTPException(status_code=400, detail="Sessão expirada. Recarregue a página e envie novamente.")
    vulgo = body.vulgo.strip()
    if not vulgo:
        raise HTTPException(status_code=400, detail="Informe a Store (ou vulgo) antes de verificar.")
    try:
        resultado = engine.check_many(body.numeros.splitlines(), record_new=True, vulgo=vulgo)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falha ao acessar o banco: {exc}") from exc
    agora = datetime.now(timezone.utc)
    try:
        stats = engine.stats()
    except Exception:
        stats = None
    payload = build_payload(resultado, agora)
    payload["stats"] = build_stats_payload(stats, agora)
    return payload
