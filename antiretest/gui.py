"""GUI mínima do anti-retest, para visualizar o veredito e o histórico."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk

from .core import DEFAULT_DB_PATH, AntiRetest, InvalidNumberError

CORES = {
    "new": "#1a7f37",
    "known": "#cf222e",
    "invalid": "#57606a",
}


class AntiRetestApp(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        db_path: str = str(DEFAULT_DB_PATH),
        *,
        log_dir: str | Path | None = None,
    ) -> None:
        super().__init__(master, padding=12)
        self.engine = AntiRetest(db_path, log_dir=log_dir)
        self.db_path = db_path
        self.numero = tk.StringVar()
        self.veredito = tk.StringVar(value="Digite a linha completa: PAN|MM|AAAA|CVV.")
        self.detalhe = tk.StringVar(value="")
        self.resumo = tk.StringVar(value="")

        self.grid(sticky="nsew")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        self._montar_entrada()
        self._montar_veredito()
        self._montar_historico()
        self._montar_rodape()
        self.atualizar()

    def _montar_entrada(self) -> None:
        caixa = ttk.LabelFrame(self, text="Verificação", padding=10)
        caixa.grid(row=0, column=0, sticky="ew")
        caixa.columnconfigure(1, weight=1)

        ttk.Label(caixa, text="Linha completa (PAN|MM|AAAA|CVV)").grid(row=0, column=0, sticky="w")
        entrada = ttk.Entry(caixa, textvariable=self.numero, font=("Consolas", 12), width=26)
        entrada.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        entrada.bind("<Return>", lambda _e: self.verificar())
        entrada.focus_set()

        botoes = ttk.Frame(caixa)
        botoes.grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Button(botoes, text="Verificar e registrar", command=self.verificar).pack(side="left")
        ttk.Button(
            botoes, text="Consultar sem gravar", command=lambda: self.verificar(record=False)
        ).pack(side="left", padx=6)
        ttk.Button(botoes, text="Esquecer", command=self.esquecer).pack(side="left")

    def _montar_veredito(self) -> None:
        self.rotulo = ttk.Label(self, textvariable=self.veredito, font=("Segoe UI", 12, "bold"))
        self.rotulo.grid(row=1, column=0, sticky="w", pady=(12, 2))
        ttk.Label(self, textvariable=self.detalhe, foreground="#57606a").grid(
            row=2, column=0, sticky="w"
        )

    def _montar_historico(self) -> None:
        caixa = ttk.LabelFrame(self, text="Histórico", padding=8)
        caixa.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        caixa.columnconfigure(0, weight=1)
        caixa.rowconfigure(0, weight=1)

        colunas = ("numero", "adicionado", "dias", "tentativas", "ultima")
        self.tabela = ttk.Treeview(caixa, columns=colunas, show="headings", height=9)
        titulos = {
            "numero": ("Número", 170),
            "adicionado": ("Adicionado em", 120),
            "dias": ("Dias atrás", 80),
            "tentativas": ("Tentativas", 90),
            "ultima": ("Última consulta", 120),
        }
        for coluna, (titulo, largura) in titulos.items():
            self.tabela.heading(coluna, text=titulo)
            self.tabela.column(coluna, width=largura, anchor="center")
        self.tabela.column("numero", anchor="w")
        self.tabela.grid(row=0, column=0, sticky="nsew")

        barra = ttk.Scrollbar(caixa, orient="vertical", command=self.tabela.yview)
        self.tabela.configure(yscrollcommand=barra.set)
        barra.grid(row=0, column=1, sticky="ns")

    def _montar_rodape(self) -> None:
        rodape = ttk.Frame(self)
        rodape.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        rodape.columnconfigure(0, weight=1)
        ttk.Label(rodape, textvariable=self.resumo, foreground="#57606a").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(rodape, text="Atualizar", command=self.atualizar).grid(row=0, column=1)

    def _mostrar(self, texto: str, detalhe: str, cor: str) -> None:
        self.veredito.set(texto)
        self.detalhe.set(detalhe)
        self.rotulo.configure(foreground=cor)

    def verificar(self, *, record: bool = True) -> None:
        try:
            resultado = self.engine.check(self.numero.get(), record=record)
        except InvalidNumberError as erro:
            self._mostrar("NÚMERO INVÁLIDO", str(erro), CORES["invalid"])
            return

        titulos = {
            "new": "NUNCA ADICIONADO" if not record else "NOVO — registrado agora",
            "known": "JÁ ESTÁ NO BANCO",
        }
        detalhe = (
            f"{resultado.masked} · validade {resultado.expiry}"
            f" · adicionado em {resultado.added_on.isoformat()}"
            f" · {resultado.days_since_added} dia(s) atrás"
            f" · {resultado.attempts} tentativa(s)"
        )
        if resultado.expired:
            detalhe += " · VENCIDO"
        if not record:
            detalhe += " · (não gravado)"
        self._mostrar(titulos[resultado.status], detalhe, CORES[resultado.status])
        self.atualizar()

    def esquecer(self) -> None:
        try:
            removido = self.engine.forget(self.numero.get())
        except InvalidNumberError as erro:
            self._mostrar("NÚMERO INVÁLIDO", str(erro), CORES["invalid"])
            return
        texto = "REMOVIDO DO HISTÓRICO" if removido else "NÃO ESTAVA NO HISTÓRICO"
        self._mostrar(texto, "", CORES["invalid"])
        self.atualizar()

    def atualizar(self) -> None:
        self.tabela.delete(*self.tabela.get_children())
        for registro in self.engine.recent(limit=100):
            self.tabela.insert(
                "",
                "end",
                values=(
                    registro["masked"],
                    registro["added_on"].isoformat(),
                    registro["days_since_added"],
                    registro["attempts"],
                    registro["last_seen_at"].date().isoformat(),
                ),
            )
        stats = self.engine.stats()
        self.resumo.set(
            f"{self.db_path} · {stats['total']} número(s) · {stats['attempts']} consulta(s)"
            f" · {stats['retested']} repetido(s)"
        )

    def destroy(self) -> None:
        self.engine.close()
        super().destroy()


def run(db_path: str = str(DEFAULT_DB_PATH), *, log_dir: str | Path | None = None) -> None:
    root = tk.Tk()
    root.title("Anti-retest")
    root.geometry("720x560")
    root.minsize(640, 480)
    AntiRetestApp(root, db_path, log_dir=log_dir)
    root.mainloop()


if __name__ == "__main__":
    run()
