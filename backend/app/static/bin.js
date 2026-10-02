(function () {
    'use strict';

    var $ = function (id) { return document.getElementById(id); };
    var form = $('form-bin');
    var campo = $('bins');
    if (!form || !campo) { return; }

    var gutter = $('gutter-bin');
    var mLinhas = $('bm-linhas'), mBins = $('bm-bins');
    var sLinhas = $('bs-linhas'), sBins = $('bs-bins');
    var botao = $('bin-enviar');
    var botaoOriginal = botao.innerHTML;
    var binCorpo = $('bin-corpo');
    var binSub = $('bin-sub');
    var binFiltros = $('bin-filtros');
    var seg = binFiltros.querySelector('.seg');

    function br(v) { return Number(v).toLocaleString('pt-BR'); }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function soDigitos(linha) { return (linha.match(/\d/g) || []).join(''); }

    /* ---------------- contadores ao vivo ---------------- */
    var ultimaQtd = -1;
    function desenharGutter(qtd) {
        if (qtd === ultimaQtd) { return; }
        ultimaQtd = qtd;
        var partes = [];
        for (var i = 1; i <= qtd; i++) { partes.push('<span>' + (i < 10 ? '0' + i : i) + '</span>'); }
        gutter.innerHTML = partes.join('');
    }

    function medir() {
        var todas = campo.value.split('\n');
        var linhas = 0;
        var bins = {};
        for (var i = 0; i < todas.length; i++) {
            if (todas[i].trim() === '') { continue; }
            linhas++;
            var d = soDigitos(todas[i]);
            if (d.length >= 6) { bins[d.slice(0, 6)] = true; }
        }
        var distintos = Object.keys(bins).length;
        mLinhas.textContent = br(linhas);
        mBins.textContent = br(distintos);
        sLinhas.textContent = br(linhas);
        sBins.textContent = br(distintos);
        desenharGutter(Math.min(campo.value === '' ? 3 : todas.length, 9999));
        gutter.scrollTop = campo.scrollTop;
    }

    var MEDIR_ADIADO = 50000, timer = null;
    function agendarMedir() {
        clearTimeout(timer);
        if (campo.value.length < MEDIR_ADIADO) { medir(); return; }
        timer = setTimeout(medir, 180);
    }
    campo.addEventListener('input', agendarMedir);
    campo.addEventListener('scroll', function () { gutter.scrollTop = campo.scrollTop; });
    campo.addEventListener('keydown', function (ev) {
        if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') { form.requestSubmit(); }
    });
    $('bin-limpar').addEventListener('click', function () { campo.value = ''; medir(); campo.focus(); });
    medir();

    /* ---------------- resultados ---------------- */
    var SITUACOES = {
        encontrado: { rotulo: 'Encontrado', tom: 'ok' },
        nao_encontrado: { rotulo: 'Não encontrado', tom: 'ambar' },
        invalido: { rotulo: 'Inválido', tom: 'erro' },
        erro: { rotulo: 'Falha', tom: 'indigo' }
    };
    var FILTROS = [
        ['todos', 'Todos'], ['encontrado', 'Encontrados'],
        ['nao_encontrado', 'Não encontrados'], ['invalido', 'Inválidos'], ['erro', 'Falhas']
    ];

    var LOTE = 200;
    var estado = { itens: [], lista: [], mostrados: 0 };
    var corpoTabela = null, sentinela = null, observador = null;

    var NULO = '<span class="nulo">—</span>';
    var ICO_COPIAR = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"'
        + ' stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11.5" height="11.5" rx="2.5"/>'
        + '<path d="M5.5 15H5a1.5 1.5 0 0 1-1.5-1.5v-8A1.5 1.5 0 0 1 5 4h8A1.5 1.5 0 0 1 14.5 5.5V6"/></svg>';
    var CHECK = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"'
        + ' stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="M2.8 8.6l3.1 3.1 7.3-7.4"/></svg>';
    function cel(v) { return v ? esc(v) : NULO; }

    function linhaHtml(it, i) {
        var sit = SITUACOES[it.situacao] || SITUACOES.erro;
        var cartao = '<span class="num">' + esc(it.cartao || '') + '</span>'
            + '<button type="button" class="copiar" aria-label="Copiar cartão" data-i="' + i + '">' + ICO_COPIAR + '</button>';
        var bin = it.bin
            ? '<span class="num">' + esc(it.bin) + '</span>'
            : '<span class="duo duo-motivo"><strong>Linha inválida</strong><span>Número, validade ou CVV</span></span>';
        return '<tr data-situacao="' + it.situacao + '">'
            + '<td data-label="Cartão"><div class="cel-num"><span class="idx">' + it.linha + '</span>' + cartao + '</div></td>'
            + '<td data-label="BIN">' + bin + '</td>'
            + '<td data-label="Bandeira">' + cel(it.bandeira) + '</td>'
            + '<td data-label="Tipo">' + cel(it.tipo) + '</td>'
            + '<td data-label="Banco">' + cel(it.banco) + '</td>'
            + '<td data-label="Produto">' + cel(it.produto) + '</td>'
            + '<td data-label="País">' + cel(it.pais) + '</td>'
            + '<td data-label="Status"><span class="selo ' + sit.tom + '">' + sit.rotulo + '</span></td>'
            + '</tr>';
    }

    function mostrarMais() {
        var fim = Math.min(estado.mostrados + LOTE, estado.lista.length);
        var html = '';
        for (var i = estado.mostrados; i < fim; i++) { html += linhaHtml(estado.lista[i], i); }
        corpoTabela.insertAdjacentHTML('beforeend', html);
        estado.mostrados = fim;
        sentinela.hidden = fim >= estado.lista.length;
    }

    function montarTabela() {
        if (observador) { observador.disconnect(); }
        binCorpo.innerHTML = '<div class="tab-scroll"><table class="res-tab"><thead><tr>'
            + '<th class="c-numero">Cartão</th><th>BIN</th><th>Bandeira</th><th>Tipo</th><th>Banco</th>'
            + '<th>Produto</th><th>País</th><th class="c-status">Status</th>'
            + '</tr></thead><tbody id="bin-tbody"></tbody></table>'
            + '<div class="mais" id="bin-mais">Carregando mais linhas…</div></div>';
        corpoTabela = $('bin-tbody');
        sentinela = $('bin-mais');
        estado.mostrados = 0;
        mostrarMais();
        if ('IntersectionObserver' in window) {
            observador = new IntersectionObserver(function (e) {
                if (e[0].isIntersecting && estado.mostrados < estado.lista.length) { mostrarMais(); }
            }, { rootMargin: '400px 0px' });
            observador.observe(sentinela);
        } else {
            while (estado.mostrados < estado.lista.length) { mostrarMais(); }
        }
    }

    function descrever(qtd) {
        return br(qtd) + (qtd === 1 ? ' linha' : ' linhas');
    }

    function filtrar(alvo) {
        estado.lista = alvo === 'todos'
            ? estado.itens
            : estado.itens.filter(function (it) { return it.situacao === alvo; });
        Array.prototype.forEach.call(seg.children, function (b) {
            b.setAttribute('aria-pressed', b.dataset.alvo === alvo ? 'true' : 'false');
        });
        binSub.textContent = descrever(estado.lista.length);
        montarTabela();
    }

    function vazio(titulo, texto) {
        binFiltros.hidden = true;
        binCorpo.innerHTML = '<div class="vazio"><h3>' + esc(titulo) + '</h3><p>' + esc(texto) + '</p></div>';
    }

    function renderizar(dados) {
        estado.itens = dados.itens || [];
        var pn = $('pn-bin');
        pn.classList.remove('surge'); void pn.offsetWidth; pn.classList.add('surge');
        if (!estado.itens.length) {
            binSub.textContent = descrever(0);
            vazio('Nenhuma linha processada', 'O lote enviado não continha linhas utilizáveis.');
            return;
        }
        var totais = { todos: estado.itens.length };
        var resumo = dados.resumo || {};
        for (var k in resumo) { totais[k] = resumo[k]; }
        seg.innerHTML = FILTROS.map(function (f) {
            return '<button type="button" data-alvo="' + f[0] + '" aria-pressed="false"'
                + (totais[f[0]] ? '' : ' disabled') + '>' + f[1] + ' <b>' + br(totais[f[0]] || 0) + '</b></button>';
        }).join('');
        binFiltros.hidden = false;
        filtrar('todos');
    }

    function linhaCopia(it) {
        var cartao = it.cartao || '';
        if (it.situacao === 'encontrado') {
            return cartao + ' ' + [it.bin || '', it.bandeira || '', it.tipo || '',
                it.banco || '', it.produto || '', it.pais || ''].join('\t');
        }
        if (it.situacao === 'nao_encontrado') { return cartao + ' ' + (it.bin || '') + '\tNÃO ENCONTRADO'; }
        if (it.situacao === 'invalido') { return cartao + '\tINVÁLIDO'; }
        return cartao + '\tFALHA';
    }

    seg.addEventListener('click', function (ev) {
        var b = ev.target.closest('button[data-alvo]');
        if (b && !b.disabled) { filtrar(b.dataset.alvo); }
    });

    var botaoCopiarTudo = $('bin-copiar-tudo');
    if (botaoCopiarTudo) {
        var rotuloCopiar = botaoCopiarTudo.querySelector('span');
        botaoCopiarTudo.addEventListener('click', function () {
            if (!estado.lista.length || !navigator.clipboard) { return; }
            var texto = estado.lista.map(linhaCopia).join('\n');
            navigator.clipboard.writeText(texto).then(function () {
                var antes = rotuloCopiar.textContent;
                rotuloCopiar.textContent = 'Copiado!';
                botaoCopiarTudo.classList.add('feito');
                setTimeout(function () { rotuloCopiar.textContent = antes; botaoCopiarTudo.classList.remove('feito'); }, 1400);
            });
        });
    }
    binCorpo.addEventListener('click', function (ev) {
        var copiar = ev.target.closest('.copiar');
        if (copiar) {
            var it = estado.lista[+copiar.dataset.i];
            if (!it || !navigator.clipboard) { return; }
            navigator.clipboard.writeText(it.cartao || '').then(function () {
                copiar.classList.add('feito');
                copiar.innerHTML = CHECK;
                setTimeout(function () { copiar.classList.remove('feito'); copiar.innerHTML = ICO_COPIAR; }, 1400);
            });
            return;
        }
        var linha = ev.target.closest('tbody tr');
        if (linha) { linha.classList.toggle('sel'); }
    });

    function esqueleto() {
        var larguras = [200, 60, 90, 70, 150, 120, 60, 92];
        var html = '<div class="skel">';
        for (var i = 0; i < 6; i++) {
            html += '<div class="skel-l">';
            for (var j = 0; j < larguras.length; j++) {
                html += '<span class="skel-b" style="width:' + larguras[j] + 'px"></span>';
            }
            html += '</div>';
        }
        binFiltros.hidden = true;
        binCorpo.innerHTML = html + '</div>';
        binSub.textContent = 'Consultando…';
    }

    function ocupado(sim) {
        botao.disabled = sim;
        botao.innerHTML = sim
            ? '<svg class="girando" width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"'
              + ' stroke-width="2" stroke-linecap="round"><path d="M8 1.8a6.2 6.2 0 1 0 6.2 6.2"/></svg><span>Consultando…</span>'
            : botaoOriginal;
    }

    var alertaAtual = null;
    function alertar(msg) {
        if (alertaAtual) { alertaAtual.remove(); alertaAtual = null; }
        if (!msg) { return; }
        alertaAtual = document.createElement('div');
        alertaAtual.className = 'alerta';
        alertaAtual.setAttribute('role', 'alert');
        alertaAtual.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
            + ' stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16.2v.01"/></svg>'
            + '<div>' + esc(msg) + '</div>';
        document.querySelector('.app').prepend(alertaAtual);
        alertaAtual.scrollIntoView({ block: 'nearest' });
    }

    form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        if (!window.fetch) { return; }
        ocupado(true);
        alertar(null);
        esqueleto();
        fetch('/bin/consultar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ csrf: form.elements.csrf.value, linhas: campo.value })
        }).then(function (resp) {
            return resp.json().catch(function () { return {}; }).then(function (dados) {
                if (!resp.ok) { throw new Error(dados.detail || 'Falha ao consultar (HTTP ' + resp.status + ').'); }
                return dados;
            });
        }).then(function (dados) {
            renderizar(dados);
        }).catch(function (err) {
            alertar(err.message || 'Falha de conexão com o servidor.');
            binSub.textContent = 'Aguardando consulta';
            vazio('Consulta não concluída', 'Corrija o problema acima e tente novamente.');
        }).then(function () {
            ocupado(false);
        });
    });
})();
