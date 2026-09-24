"""Schemas da API REST."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CheckRequest(BaseModel):
    vulgo: str = Field(..., min_length=1, max_length=40, description="Store ou vulgo de quem consulta")
    lines: list[str] = Field(..., min_length=1, description="Linhas número|mês|ano|cvv ou hash SHA-256")
    record: bool = Field(True, description="Gravar novos e incrementar tentativas")


class VerificarRequest(BaseModel):
    csrf: str = ""
    vulgo: str = Field("", max_length=40)
    numeros: str = ""


class CheckItem(BaseModel):
    line: int
    status: str
    masked: str | None = None
    cc_full: str = ""
    fingerprint: str | None = None
    is_retest: bool | None = None
    added_on: str | None = None
    days_since_added: int | None = None
    attempts: int | None = None
    expiry: str | None = None
    expired: bool | None = None
    vulgo: str | None = None
    reason: str | None = None
    first_line: int | None = None


class CheckResponse(BaseModel):
    total: int
    new: int
    known: int
    duplicated: int
    invalid: int
    items: list[CheckItem]


class StatsResponse(BaseModel):
    total: int
    attempts: int
    repetidos: int
    retested: int
    first_day: str | None
    last_day: str | None
