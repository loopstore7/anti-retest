#!/usr/bin/env python3
"""Gera usuário/senha forte CX2 e imprime hash para .env (não commitar senha)."""

from __future__ import annotations

import hashlib
import secrets
import sys
from pathlib import Path

PBKDF2_ITERS = 600_000


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return f"pbkdf2_sha256${PBKDF2_ITERS}${salt.hex()}${digest.hex()}"


def main() -> int:
    user = "cx2admin"
    password = secrets.token_urlsafe(24)
    pwd_hash = hash_password(password)
    # Docker Compose interpreta $ no .env — dobrar cada $
    env_hash = pwd_hash.replace("$", "$$")
    print(f"CX2_ADMIN_USER={user}")
    print(f"CX2_ADMIN_PASSWORD_HASH={env_hash}")
    cred_path = Path(__file__).resolve().parents[1] / "CREDENCIAIS_CX2.txt"
    cred_path.write_text(
        "Anti-retest — painel CX2 (guarde em local seguro; não commitar)\n\n"
        f"URL: https://admin.antiretest.com/\n"
        f"Usuário: {user}\n"
        f"Senha: {password}\n",
        encoding="utf-8",
    )
    cred_path.chmod(0o600)
    print(f"# Credenciais também em: {cred_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
