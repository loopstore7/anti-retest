"""Painel administrativo oculto — gestão de cartões da base anti-retest.

Acesso restrito por host (admin.antiretest.com), autenticação forte (PBKDF2),
CSRF em toda ação de escrita, rate limit de login e sessão com expiração.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

PBKDF2_ITERS = 600_000
SESSION_ADMIN = "cx2_admin_ok"
SESSION_ADMIN_AT = "cx2_admin_at"
SESSION_CSRF = "cx2_csrf"
SESSION_MAX_AGE_SEC = 4 * 3600
LOGIN_WINDOW_SEC = 900
LOGIN_MAX_FAILS = 8

_failures: dict[str, list[float]] = {}


def _client_key(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return fwd or (request.client.host if request.client else "unknown")


def _login_blocked(key: str) -> bool:
    now = time.time()
    hits = [t for t in _failures.get(key, []) if now - t < LOGIN_WINDOW_SEC]
    _failures[key] = hits
    return len(hits) >= LOGIN_MAX_FAILS


def _record_fail(key: str) -> None:
    _failures.setdefault(key, []).append(time.time())


def _clear_fails(key: str) -> None:
    _failures.pop(key, None)


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return f"pbkdf2_sha256${PBKDF2_ITERS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(got, expected)


def admin_configured() -> bool:
    user = os.environ.get("CX2_ADMIN_USER", "").strip()
    pwd_hash = os.environ.get("CX2_ADMIN_PASSWORD_HASH", "").strip()
    return bool(user and pwd_hash)


def _admin_host() -> str:
    return os.environ.get("ADMIN_HOST", "").strip().lower()


def _request_host(request: Request) -> str:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    return host.split(":")[0].strip().lower()


def is_admin_site(request: Request) -> bool:
    """Subdomínio dedicado ao painel (ex.: admin.antiretest.com)."""
    expected = _admin_host()
    return bool(expected) and _request_host(request) == expected


def host_allowed(request: Request) -> bool:
    """Rotas /admin/* só no host configurado.

    Sem ADMIN_HOST definido (dev local) libera qualquer host.
    """
    expected = _admin_host()
    if not expected:
        return True
    return _request_host(request) == expected


def _admin_site_path_ok(path: str) -> bool:
    if path in ("/", "/health"):
        return True
    if path.startswith("/static/"):
        return True
    return path == "/admin" or path.startswith("/admin/")


def install_admin_site_middleware(app) -> None:
    """No subdomínio admin, bloqueia o site público (verificação, docs, etc.)."""

    @app.middleware("http")
    async def _admin_site_only(request: Request, call_next):
        if is_admin_site(request) and not _admin_site_path_ok(request.url.path):
            return PlainTextResponse("Not Found", status_code=404)
        return await call_next(request)


def require_host(request: Request) -> None:
    if not host_allowed(request):
        # Para quem não está no host certo, o admin simplesmente não existe.
        raise HTTPException(status_code=404, detail="Not Found")


def require_admin(request: Request) -> None:
    require_host(request)
    if not request.session.get(SESSION_ADMIN):
        raise HTTPException(status_code=401, detail="Não autenticado")
    login_at = float(request.session.get(SESSION_ADMIN_AT) or 0)
    if time.time() - login_at > SESSION_MAX_AGE_SEC:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Sessão expirada")


def ensure_csrf(request: Request) -> str:
    token = request.session.get(SESSION_CSRF)
    if not token:
        token = secrets.token_hex(24)
        request.session[SESSION_CSRF] = token
    return str(token)


def check_csrf(request: Request, token: str) -> None:
    if not token or not hmac.compare_digest(str(request.session.get(SESSION_CSRF) or ""), token):
        raise HTTPException(status_code=400, detail="CSRF inválido")


_root_login_get: Any = None
_root_login_post: Any = None


def admin_root_login_get(request: Request) -> HTMLResponse:
    assert _root_login_get is not None
    return _root_login_get(request)


def admin_root_login_post(
    request: Request,
    csrf: str = "",
    username: str = "",
    password: str = "",
) -> HTMLResponse:
    assert _root_login_post is not None
    return _root_login_post(request, csrf, username, password)


def register_cx2_routes(
    app_router: APIRouter,
    templates: Jinja2Templates,
    *,
    get_engine,
    page_ctx,
    n_fmt,
) -> None:
    global _root_login_get, _root_login_post

    def ctx(request: Request, *, aba: str = "", **extra: Any) -> dict[str, Any]:
        base = page_ctx(request, aba_ativa=aba, **extra)
        base.setdefault("n", n_fmt)
        return base

    def login_page(request: Request, *, erro: str | None = None, login_action: str = "/") -> HTMLResponse:
        require_host(request)
        if not admin_configured():
            raise HTTPException(status_code=503, detail="Admin não configurado no servidor")
        if request.session.get(SESSION_ADMIN):
            return RedirectResponse("/admin/painel", status_code=302)
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            ctx(request, erro=erro, csrf=ensure_csrf(request), login_action=login_action),
        )

    def login_submit(
        request: Request,
        csrf: str,
        username: str,
        password: str,
        *,
        login_action: str = "/",
    ) -> HTMLResponse:
        require_host(request)
        if not admin_configured():
            raise HTTPException(status_code=503, detail="Admin não configurado")
        check_csrf(request, csrf)
        key = _client_key(request)
        if _login_blocked(key):
            return templates.TemplateResponse(
                request,
                "admin_login.html",
                ctx(
                    request,
                    erro="Muitas tentativas. Aguarde 15 minutos.",
                    csrf=ensure_csrf(request),
                    login_action=login_action,
                ),
                status_code=429,
            )
        user_ok = hmac.compare_digest(username.strip(), os.environ["CX2_ADMIN_USER"].strip())
        pwd_ok = verify_password(password, os.environ["CX2_ADMIN_PASSWORD_HASH"].strip())
        if not (user_ok and pwd_ok):
            _record_fail(key)
            return templates.TemplateResponse(
                request,
                "admin_login.html",
                ctx(
                    request,
                    erro="Usuário ou senha incorretos.",
                    csrf=ensure_csrf(request),
                    login_action=login_action,
                ),
                status_code=401,
            )
        _clear_fails(key)
        request.session[SESSION_ADMIN] = True
        request.session[SESSION_ADMIN_AT] = time.time()
        ensure_csrf(request)
        return RedirectResponse("/admin/painel", status_code=303)

    def root_login_get(request: Request) -> HTMLResponse:
        return login_page(request, login_action="/")

    def root_login_post(request: Request, csrf: str, username: str, password: str) -> HTMLResponse:
        return login_submit(request, csrf, username, password, login_action="/")

    _root_login_get = root_login_get
    _root_login_post = root_login_post

    # -- Acesso -------------------------------------------------------
    @app_router.get("/admin", response_class=HTMLResponse)
    @app_router.get("/admin/", response_class=HTMLResponse)
    def admin_legacy_root(request: Request) -> RedirectResponse:
        require_host(request)
        if request.session.get(SESSION_ADMIN):
            return RedirectResponse("/admin/painel", status_code=302)
        return RedirectResponse("/", status_code=302)

    @app_router.get("/admin/login", response_class=HTMLResponse)
    def admin_login_redirect(request: Request) -> RedirectResponse:
        require_host(request)
        return RedirectResponse("/", status_code=302)

    @app_router.post("/admin/login", response_class=HTMLResponse)
    def admin_login_post(
        request: Request,
        csrf: str = Form(""),
        username: str = Form(""),
        password: str = Form(""),
    ) -> HTMLResponse:
        return login_submit(request, csrf, username, password, login_action="/admin/login")

    @app_router.get("/admin/logout")
    def admin_logout(request: Request) -> RedirectResponse:
        require_host(request)
        request.session.clear()
        return RedirectResponse("/", status_code=302)

    # -- Painel -------------------------------------------------------
    @app_router.get("/admin/painel", response_class=HTMLResponse)
    def admin_painel(request: Request) -> HTMLResponse:
        require_admin(request)
        eng = get_engine()
        stats = eng.stats() if eng else None
        return templates.TemplateResponse(
            request,
            "admin_painel.html",
            ctx(request, aba="painel", stats=stats, csrf=ensure_csrf(request), msg=request.query_params.get("msg")),
        )

    # -- Cartões ------------------------------------------------------
    @app_router.get("/admin/cartoes", response_class=HTMLResponse)
    def admin_cartoes(request: Request) -> HTMLResponse:
        require_admin(request)
        eng = get_engine()
        if not eng:
            raise HTTPException(status_code=503, detail="Motor indisponível")
        qp = request.query_params
        busca = (qp.get("q") or "").strip()
        try:
            page = int(qp.get("page") or 1)
        except ValueError:
            page = 1
        try:
            per_page = int(qp.get("pp") or 50)
        except ValueError:
            per_page = 50
        resultado = eng.list_cards(search=busca, page=page, per_page=per_page)
        return templates.TemplateResponse(
            request,
            "admin_cartoes.html",
            ctx(
                request,
                aba="cartoes",
                busca=busca,
                lista=resultado,
                csrf=ensure_csrf(request),
                msg=qp.get("msg"),
                removidos=int(qp.get("rm") or 0),
            ),
        )

    @app_router.get("/admin/cartoes/{fingerprint}", response_class=HTMLResponse)
    def admin_cartao(request: Request, fingerprint: str) -> HTMLResponse:
        require_admin(request)
        eng = get_engine()
        if not eng:
            raise HTTPException(status_code=503, detail="Motor indisponível")
        card = eng.get_card(fingerprint)
        if not card:
            raise HTTPException(status_code=404, detail="Cartão não encontrado")
        return templates.TemplateResponse(
            request, "admin_cartao.html", ctx(request, aba="cartoes", card=card, csrf=ensure_csrf(request))
        )

    @app_router.post("/admin/cartoes/excluir")
    def admin_cartoes_excluir(
        request: Request,
        csrf: str = Form(""),
        fingerprints: list[str] = Form(default=[]),
        voltar: str = Form(""),
    ) -> RedirectResponse:
        require_admin(request)
        check_csrf(request, csrf)
        eng = get_engine()
        if not eng:
            raise HTTPException(status_code=503, detail="Motor indisponível")
        removidos = eng.delete_cards(fingerprints)
        destino = "/admin/cartoes"
        if voltar and voltar.startswith("/admin/cartoes"):
            destino = voltar
        sep = "&" if "?" in destino else "?"
        return RedirectResponse(f"{destino}{sep}msg=excluidos&rm={removidos}", status_code=303)

    # -- Manutenção (secundário) -------------------------------------
    @app_router.post("/admin/zerar-consultas")
    def admin_zerar_consultas(request: Request, csrf: str = Form(""), confirm: str = Form("")) -> RedirectResponse:
        require_admin(request)
        check_csrf(request, csrf)
        if confirm.strip().upper() != "ZERAR":
            return RedirectResponse("/admin/painel?msg=confirmacao_invalida", status_code=303)
        eng = get_engine()
        if not eng:
            raise HTTPException(status_code=503, detail="Motor indisponível")
        eng.reset_consultas_baseline()
        return RedirectResponse("/admin/painel?msg=zerado", status_code=303)
