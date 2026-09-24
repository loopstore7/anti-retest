"""Servidor web local do anti-retest, com a mesma função da GUI no navegador."""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .core import DEFAULT_DB_PATH, AntiRetest, InvalidNumberError

MAX_BODY = 1 << 20

PAGE = """<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anti-retest</title>
<style>
  :root { color-scheme: light dark; --new: #1a7f37; --known: #cf222e; --muted: #57606a; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px; font: 15px/1.5 "Segoe UI", system-ui, sans-serif; }
  main { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 0 0 16px; }
  fieldset { border: 1px solid #8886; border-radius: 8px; padding: 12px; margin: 0 0 16px; }
  legend { padding: 0 6px; color: var(--muted); }
  textarea { width: 100%; min-height: 84px; font: 14px/1.5 Consolas, monospace; padding: 8px;
             border: 1px solid #8886; border-radius: 6px; background: transparent; color: inherit; }
  .botoes { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
  button { padding: 7px 14px; border: 1px solid #8886; border-radius: 6px; cursor: pointer;
           background: #8881; color: inherit; font-size: 14px; }
  button:hover { background: #8883; }
  #vereditos { list-style: none; padding: 0; margin: 0 0 16px; }
  #vereditos li { padding: 8px 0; border-bottom: 1px solid #8883; }
  #vereditos strong { font-size: 15px; }
  #vereditos .detalhe { color: var(--muted); font-size: 13px; }
  .new { color: var(--new); } .known { color: var(--known); } .invalid { color: var(--muted); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { padding: 6px 8px; text-align: center; border-bottom: 1px solid #8883; }
  th:first-child, td:first-child { text-align: left; font-family: Consolas, monospace; }
  th { color: var(--muted); font-weight: 600; }
  footer { display: flex; justify-content: space-between; align-items: center; gap: 12px;
           color: var(--muted); font-size: 13px; margin-top: 12px; }
</style>
</head>
<body>
<main>
  <h1>Anti-retest</h1>

  <fieldset>
    <legend>Verificação</legend>
    <label for="entrada">Linha completa (PAN|MM|AAAA|CVV) — uma por linha</label>
    <textarea id="entrada" spellcheck="false" autofocus></textarea>
    <div class="botoes">
      <button data-acao="check">Verificar e registrar</button>
      <button data-acao="dry">Consultar sem gravar</button>
      <button data-acao="forget">Esquecer</button>
    </div>
  </fieldset>

  <ul id="vereditos"><li class="invalid">Digite a linha completa: PAN|MM|AAAA|CVV.</li></ul>

  <fieldset>
    <legend>Histórico</legend>
    <table>
      <thead><tr>
        <th>Número</th><th>Adicionado em</th><th>Dias atrás</th>
        <th>Tentativas</th><th>Última consulta</th>
      </tr></thead>
      <tbody id="historico"></tbody>
    </table>
  </fieldset>

  <footer><span id="resumo"></span><button id="atualizar">Atualizar</button></footer>
</main>
<script>
const $ = (id) => document.getElementById(id);

async function api(rota, corpo) {
  const opcoes = corpo
    ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(corpo) }
    : {};
  const resposta = await fetch(rota, opcoes);
  if (!resposta.ok) throw new Error(await resposta.text());
  return resposta.json();
}

function numeros() {
  return $("entrada").value.split("\\n").map((l) => l.trim()).filter(Boolean);
}

function mostrar(itens) {
  $("vereditos").replaceChildren(...itens.map((item) => {
    const li = document.createElement("li");
    const titulo = document.createElement("strong");
    titulo.className = item.status;
    titulo.textContent = item.titulo;
    li.append(titulo);
    if (item.detalhe) {
      const span = document.createElement("div");
      span.className = "detalhe";
      span.textContent = item.detalhe;
      li.append(span);
    }
    return li;
  }));
}

function veredito(r, gravou) {
  if (r.error) return { status: "invalid", titulo: "NÚMERO INVÁLIDO", detalhe: `${r.input} — ${r.error}` };
  const titulo = r.status === "known"
    ? "JÁ ESTÁ NO BANCO"
    : (gravou ? "NOVO — registrado agora" : "NUNCA ADICIONADO");
  let detalhe = `${r.masked} · validade ${r.expiry} · adicionado em ${r.added_on}`
    + ` · ${r.days_since_added} dia(s) atrás · ${r.attempts} tentativa(s)`;
  if (r.expired) detalhe += " · VENCIDO";
  if (!gravou) detalhe += " · (não gravado)";
  return { status: r.status, titulo, detalhe };
}

async function atualizar() {
  const estado = await api("/api/state");
  $("historico").replaceChildren(...estado.recent.map((r) => {
    const tr = document.createElement("tr");
    for (const valor of [r.masked, r.added_on, r.days_since_added, r.attempts, r.last_seen_on]) {
      const td = document.createElement("td");
      td.textContent = valor;
      tr.append(td);
    }
    return tr;
  }));
  const s = estado.stats;
  $("resumo").textContent = `${estado.db} · ${s.total} número(s) · ${s.attempts} consulta(s)`
    + ` · ${s.repetidos ?? s.retested} repetido(s)`;
}

async function executar(acao) {
  const lista = numeros();
  if (!lista.length) {
    mostrar([{ status: "invalid", titulo: "Digite a linha completa: PAN|MM|AAAA|CVV." }]);
    return;
  }
  try {
    if (acao === "forget") {
      const dados = await api("/api/forget", { numbers: lista });
      mostrar(dados.results.map((r) => r.error
        ? { status: "invalid", titulo: "NÚMERO INVÁLIDO", detalhe: `${r.input} — ${r.error}` }
        : { status: "invalid", titulo: r.removed ? "REMOVIDO DO HISTÓRICO" : "NÃO ESTAVA NO HISTÓRICO",
            detalhe: r.input }));
    } else {
      const gravou = acao === "check";
      const dados = await api("/api/check", { numbers: lista, record: gravou });
      mostrar(dados.results.map((r) => veredito(r, gravou)));
    }
    await atualizar();
  } catch (erro) {
    mostrar([{ status: "invalid", titulo: "ERRO NO SERVIDOR", detalhe: String(erro.message || erro) }]);
  }
}

for (const botao of document.querySelectorAll("[data-acao]")) {
  botao.addEventListener("click", () => executar(botao.dataset.acao));
}
$("atualizar").addEventListener("click", atualizar);
$("entrada").addEventListener("keydown", (evento) => {
  if (evento.key === "Enter" && !evento.shiftKey) {
    evento.preventDefault();
    executar("check");
  }
});
atualizar();
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    """Rotas do servidor: a página e a API JSON usada por ela."""

    server_version = "antiretest"
    db_path = str(DEFAULT_DB_PATH)
    log_dir: str | Path | None = None
    _local = threading.local()

    @property
    def engine(self) -> AntiRetest:
        # Uma conexão SQLite por thread: o handler roda em ThreadingHTTPServer.
        engine = getattr(_Handler._local, "engine", None)
        if engine is None:
            engine = AntiRetest(self.db_path, log_dir=self.log_dir)
            _Handler._local.engine = engine
        return engine

    def log_message(self, formato: str, *args: object) -> None:  # noqa: D102
        pass

    def do_GET(self) -> None:  # noqa: N802
        rota = urlparse(self.path)
        if rota.path in ("/", "/index.html"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif rota.path == "/api/state":
            limite = int(parse_qs(rota.query).get("limit", ["100"])[0])
            self._send_json(200, self._state(min(max(limite, 1), 500)))
        else:
            self._send_json(404, {"error": "rota não encontrada"})

    def do_POST(self) -> None:  # noqa: N802
        rota = urlparse(self.path).path
        if rota not in ("/api/check", "/api/forget"):
            self._send_json(404, {"error": "rota não encontrada"})
            return

        try:
            corpo = self._read_json()
        except ValueError as erro:
            self._send_json(400, {"error": str(erro)})
            return

        numbers = corpo.get("numbers") or ([corpo["number"]] if corpo.get("number") else [])
        if not numbers:
            self._send_json(400, {"error": "informe pelo menos um número"})
            return

        acao = self._check if rota == "/api/check" else self._forget
        record = bool(corpo.get("record", True))
        results = [acao(str(numero), record) for numero in numbers[:200]]
        self._send_json(200, {"results": results})

    def _check(self, numero: str, record: bool) -> dict[str, object]:
        try:
            resultado = self.engine.check(numero, record=record)
        except InvalidNumberError as erro:
            return {"input": numero, "error": str(erro)}
        return {
            "input": numero,
            "masked": resultado.masked,
            "fingerprint": resultado.fingerprint,
            "status": resultado.status,
            "added_on": resultado.added_on.isoformat(),
            "days_since_added": resultado.days_since_added,
            "attempts": resultado.attempts,
            "expiry": resultado.expiry,
            "expired": resultado.expired,
        }

    def _forget(self, numero: str, _record: bool) -> dict[str, object]:
        try:
            return {"input": numero, "removed": self.engine.forget(numero)}
        except InvalidNumberError as erro:
            return {"input": numero, "error": str(erro)}

    def _state(self, limite: int) -> dict[str, object]:
        recentes = [
            {
                "masked": registro["masked"],
                "added_on": registro["added_on"].isoformat(),
                "days_since_added": registro["days_since_added"],
                "attempts": registro["attempts"],
                "last_seen_on": registro["last_seen_at"].date().isoformat(),
            }
            for registro in self.engine.recent(limit=limite)
        ]
        return {"db": self.db_path, "recent": recentes, "stats": self.engine.stats()}

    def _read_json(self) -> dict[str, object]:
        tamanho = int(self.headers.get("content-length") or 0)
        if tamanho > MAX_BODY:
            raise ValueError("corpo muito grande")
        try:
            corpo = json.loads(self.rfile.read(tamanho) or b"{}")
        except json.JSONDecodeError:
            raise ValueError("JSON inválido") from None
        if not isinstance(corpo, dict):
            raise ValueError("esperado um objeto JSON")
        return corpo

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        corpo = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, corpo, "application/json; charset=utf-8")

    def _send(self, status: int, corpo: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(corpo)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(corpo)


def run(
    db_path: str = str(DEFAULT_DB_PATH),
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = True,
    log_dir: str | Path | None = None,
) -> None:
    """Sobe o servidor local e bloqueia até Ctrl+C."""
    handler = type("_BoundHandler", (_Handler,), {"db_path": db_path, "log_dir": log_dir})
    with ThreadingHTTPServer((host, port), handler) as servidor:
        endereco = f"http://{host}:{servidor.server_address[1]}"
        print(f"anti-retest em {endereco} (banco: {db_path}) — Ctrl+C para encerrar")
        if open_browser:
            threading.Timer(0.4, webbrowser.open, args=(endereco,)).start()
        try:
            servidor.serve_forever()
        except KeyboardInterrupt:
            print("\nencerrado")


if __name__ == "__main__":
    run()
