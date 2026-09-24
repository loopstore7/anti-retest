(function () {
    'use strict';

    var $ = function (id) { return document.getElementById(id); };

    /* ---------------- popovers do topo ---------------- */
    var pops = [['bt-avisos', 'pop-avisos']].map(function (par) {
        return { botao: $(par[0]), painel: $(par[1]) };
    });

    function fecharTudo(exceto) {
        pops.forEach(function (p) {
            if (p === exceto) { return; }
            p.painel.hidden = true;
            p.botao.setAttribute('aria-expanded', 'false');
        });
    }

    pops.forEach(function (p) {
        p.botao.addEventListener('click', function (ev) {
            ev.stopPropagation();
            var abrir = p.painel.hidden;
            fecharTudo(p);
            p.painel.hidden = !abrir;
            p.botao.setAttribute('aria-expanded', abrir ? 'true' : 'false');
        });
    });
    document.addEventListener('click', function (ev) {
        var dentro = pops.some(function (p) { return p.painel.contains(ev.target); });
        if (!dentro) { fecharTudo(null); }
    });
    document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') { fecharTudo(null); }
    });

    /* ---------------- editor ---------------- */
    var campo = $('numeros');
    var editor = $('editor');
    var gutter = $('gutter');
    var realce = $('realce');
    var marca = $('linhaAtiva');
    var form = $('form');

    if (!campo || !form) {
        /* pagina sem editor (ex.: documentacao) - so popovers */
        return;
    }

    var mLinhas = $('m-linhas'), mValidos = $('m-validos'), mInvalidos = $('m-invalidos');
    var sLinhas = $('s-linhas'), sValidos = $('s-validos'), sInvalidos = $('s-invalidos');
    var bOk = $('b-ok'), bAv = $('b-av');

    var ALTURA_LINHA = 22;
    var MAX_REALCE = 700;   // acima disso o realce sai e o texto volta a ser direto
    var MAX_GUTTER = 9999;
    var ultimaQtd = -1;

    function luhn(d) {
        var soma = 0;
        for (var i = 0; i < d.length; i++) {
            var v = d.charCodeAt(d.length - 1 - i) - 48;
            if (i % 2 === 1) { v *= 2; if (v > 9) { v -= 9; } }
            soma += v;
        }
        return soma % 10 === 0;
    }

    function ehAmex(d) {
        return d.length === 15 && (d.slice(0, 2) === '34' || d.slice(0, 2) === '37');
    }
    function tamCvv(d) { return ehAmex(d) ? 4 : 3; }
    function ehPan(d) {
        if (d.length === 15) { return ehAmex(d) && luhn(d); }
        return d.length === 16 && luhn(d);
    }
    function mesDe(t) {
        if (t.length < 1 || t.length > 2) { return null; }
        var v = +t;
        return v >= 1 && v <= 12 ? v : null;
    }
    function anoDe(t) {
        if (t.length === 2) { return 2000 + (+t); }
        if (t.length === 4 && +t >= 2000 && +t <= 2099) { return +t; }
        return null;
    }

    // Números da linha, campo por campo. Dentro de um campo, espaço, ponto,
    // hífen e sublinhado são só formatação; letra encerra o número.
    function numerosDe(linha) {
        var sep = /[|;,:/\\\t]+/g;
        var campos = [];
        var ini = 0;
        var m;
        while ((m = sep.exec(linha)) !== null) {
            campos.push([ini, m.index]);
            ini = m.index + m[0].length;
        }
        campos.push([ini, linha.length]);

        var lista = [];
        for (var i = 0; i < campos.length; i++) {
            var atual = '', comeco = -1, fim = -1;
            for (var j = campos[i][0]; j < campos[i][1]; j++) {
                var c = linha.charCodeAt(j);
                if (c >= 48 && c <= 57) {
                    if (atual === '') { comeco = j; }
                    atual += linha.charAt(j);
                    fim = j + 1;
                } else if (' \t._-'.indexOf(linha.charAt(j)) === -1 && atual !== '') {
                    lista.push({ d: atual, ini: comeco, fim: fim });
                    atual = '';
                }
            }
            if (atual !== '') { lista.push({ d: atual, ini: comeco, fim: fim }); }
        }
        return lista;
    }

    function acharValidadeCvv(lista, cvvLen) {
        for (var i = 0; i < lista.length; i++) {
            var t = lista[i].d;
            if ((t.length === 4 || t.length === 6)
                && mesDe(t.slice(0, 2)) !== null && anoDe(t.slice(2)) !== null
                && temCvv(lista, i + 1, cvvLen)) {
                return true;
            }
            if (mesDe(t) === null) { continue; }
            for (var j = i + 1; j < lista.length; j++) {
                if (anoDe(lista[j].d) === null) { continue; }
                if (temCvv(lista, j + 1, cvvLen)) { return true; }
            }
        }
        return false;
    }
    function temCvv(lista, desde, cvvLen) {
        for (var k = desde; k < lista.length; k++) {
            if (lista[k].d.length === cvvLen) { return true; }
        }
        return false;
    }

    // Tudo emendado, sem separador: PAN no começo, depois MM, ano e CVV.
    function umBlocoSo(token, linha) {
        var d = token.d;
        var tamanhos = [16, 15];
        for (var i = 0; i < tamanhos.length; i++) {
            var pan = d.slice(0, tamanhos[i]);
            if (!ehPan(pan)) { continue; }
            var resto = d.slice(tamanhos[i]);
            var anos = [4, 2];
            for (var a = 0; a < anos.length; a++) {
                if (resto.length !== 2 + anos[a] + tamCvv(pan)) { continue; }
                if (mesDe(resto.slice(0, 2)) !== null && anoDe(resto.slice(2, 2 + anos[a])) !== null) {
                    return [token.ini, fimDoDigito(linha, token.ini, tamanhos[i])];
                }
            }
        }
        return null;
    }
    function fimDoDigito(linha, ini, quantos) {
        var vistos = 0;
        for (var i = ini; i < linha.length; i++) {
            var c = linha.charCodeAt(i);
            if (c >= 48 && c <= 57) {
                vistos++;
                if (vistos === quantos) { return i + 1; }
            }
        }
        return linha.length;
    }

    // Mesma regra do servidor: a linha só vale com PAN, validade e CVV.
    // Devolve a faixa do PAN para o realce, ou null se faltar algo.
    function ehHash(linha) {
        return /^[a-f0-9]{64}$/i.test((linha || '').trim());
    }

    function acharPan(linha) {
        if (ehHash(linha)) { return [0, linha.trim().length]; }
        var lista = numerosDe(linha).slice(0, 12);
        for (var i = 0; i < lista.length; i++) {
            if (!ehPan(lista[i].d)) { continue; }
            var resto = lista.slice(0, i).concat(lista.slice(i + 1));
            if (acharValidadeCvv(resto, tamCvv(lista[i].d))) {
                return [lista[i].ini, lista[i].fim];
            }
        }
        if (lista.length === 1) { return umBlocoSo(lista[0], linha); }
        return null;
    }

    function escapar(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function apagar(s) {
        return escapar(s).replace(/([|;,:/\\]+)/g, '<s>$1</s>');
    }
    function realcarLinha(linha, faixa) {
        if (linha === '') { return ''; }
        if (faixa === null) { return '<i>' + apagar(linha) + '</i>'; }
        return '<i>' + apagar(linha.slice(0, faixa[0])) + '</i>'
            + '<b>' + escapar(linha.slice(faixa[0], faixa[1])) + '</b>'
            + '<i>' + apagar(linha.slice(faixa[1])) + '</i>';
    }

    function desenharGutter(qtd) {
        if (qtd === ultimaQtd) { return; }
        ultimaQtd = qtd;
        var partes = [];
        for (var i = 1; i <= qtd; i++) { partes.push('<span>' + (i < 10 ? '0' + i : i) + '</span>'); }
        gutter.innerHTML = partes.join('');
    }

    function posicionarLinhaAtiva() {
        var indice = campo.value.slice(0, campo.selectionStart).split('\n').length - 1;
        marca.style.transform = 'translateY(' + (indice * ALTURA_LINHA - campo.scrollTop) + 'px)';
    }

    function sincronizarScroll() {
        gutter.scrollTop = campo.scrollTop;
        realce.scrollTop = campo.scrollTop;
        realce.scrollLeft = campo.scrollLeft;
        posicionarLinhaAtiva();
    }

    function br(v) { return v.toLocaleString('pt-BR'); }

    function medir() {
        var bruto = campo.value;
        var todas = bruto.split('\n');
        var leve = todas.length <= MAX_REALCE;
        editor.classList.toggle('sem-realce', !leve);

        var validos = 0, uteis = 0;
        var saida = leve ? [] : null;

        for (var i = 0; i < todas.length; i++) {
            var linha = todas[i];
            var vazia = linha.trim() === '';
            var faixa = vazia ? null : acharPan(linha);
            if (!vazia) {
                uteis++;
                if (faixa !== null || ehHash(linha)) { validos++; }
            }
            if (leve) { saida.push(realcarLinha(linha, faixa)); }
        }
        if (leve) { realce.innerHTML = saida.join('\n'); }

        var invalidos = uteis - validos;
        mLinhas.textContent = br(uteis);
        mValidos.textContent = br(validos);
        mInvalidos.textContent = br(invalidos);
        sLinhas.textContent = br(uteis);
        sValidos.textContent = br(validos);
        sInvalidos.textContent = br(invalidos);

        bOk.style.width = uteis ? (validos / uteis * 100) + '%' : '0';
        bAv.style.width = uteis ? (invalidos / uteis * 100) + '%' : '0';

        desenharGutter(Math.min(bruto === '' ? 3 : todas.length, MAX_GUTTER));
        posicionarLinhaAtiva();
    }

    // Em lotes grandes, medir a cada tecla trava a digitação: espera o usuário parar.
    var MEDIR_ADIADO = 50000;
    var timerMedir = null;
    function agendarMedir() {
        clearTimeout(timerMedir);
        if (campo.value.length < MEDIR_ADIADO) { medir(); return; }
        timerMedir = setTimeout(medir, 180);
    }

    campo.addEventListener('focus', function () { editor.classList.add('focado'); posicionarLinhaAtiva(); });
    campo.addEventListener('blur', function () { editor.classList.remove('focado'); });
    campo.addEventListener('scroll', sincronizarScroll);
    campo.addEventListener('input', agendarMedir);
    campo.addEventListener('click', posicionarLinhaAtiva);
    campo.addEventListener('keyup', posicionarLinhaAtiva);
    medir();

    $('limpar').addEventListener('click', function () {
        campo.value = '';
        medir();
        campo.focus();
    });

    campo.addEventListener('keydown', function (ev) {
        if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') { form.requestSubmit(); }
    });

    /* ---------------- resultados ---------------- */
    var resCorpo = $('res-corpo');
    var resSub = $('res-sub');
    var resFiltros = $('res-filtros');
    var seg = resFiltros.querySelector('.seg');
    var botaoEnviar = $('enviar');
    var botaoOriginal = botaoEnviar.innerHTML;

    var LOTE = 200;
    var SITUACOES = {
        novo: { rotulo: 'Novo', tom: 'ok' },
        existente: { rotulo: 'Existente', tom: 'ambar' },
        repetido: { rotulo: 'Repetido', tom: 'indigo' },
        invalido: { rotulo: 'Inválido', tom: 'erro' }
    };
    var FILTROS = [
        ['todos', 'Todos'], ['novo', 'Novos'], ['existente', 'Existentes'],
        ['repetido', 'Repetidos'], ['invalido', 'Inválidos']
    ];
    var ICO_COPIAR = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"'
        + ' stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11.5" height="11.5" rx="2.5"/>'
        + '<path d="M5.5 15H5a1.5 1.5 0 0 1-1.5-1.5v-8A1.5 1.5 0 0 1 5 4h8A1.5 1.5 0 0 1 14.5 5.5V6"/></svg>';
    var CHECK = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"'
        + ' stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="M2.8 8.6l3.1 3.1 7.3-7.4"/></svg>';

    var estado = { itens: [], lista: [], mostrados: 0, hora: '', rotulo: '' };
    var corpoTabela = null, sentinela = null, observador = null;

    function esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function descrever(qtd) {
        return br(qtd) + (qtd === 1 ? ' registro encontrado' : ' registros encontrados');
    }

    function grupos(digitos, separador) {
        var out = [];
        for (var i = 0; i < digitos.length; i += 4) { out.push(digitos.slice(i, i + 4)); }
        return out.join(separador);
    }

    function numeroHtml(it) {
        if (it.completo) {
            var partes = it.numero.split('|');
            var html = grupos(esc(partes[0]), '<span class="nb-gap"></span>');
            for (var i = 1; i < partes.length; i++) { html += '<span class="nb-sep">|</span>' + esc(partes[i]); }
            return html;
        }
        return grupos(esc(it.numero), '<span class="nb-gap"></span>').replace(/\*/g, '<span class="nb-mk">•</span>');
    }

    function textoCopia(it) {
        return it.completo ? it.numero : grupos(it.numero, ' ').replace(/\*/g, '•');
    }

    function duo(forte, fraco, titulo) {
        return '<div class="duo"' + (titulo ? ' title="' + esc(titulo) + '"' : '') + '><strong>' + esc(forte)
            + '</strong><span>' + esc(fraco) + '</span></div>';
    }

    var NULO = '<span class="nulo">—</span>';

    function linhaHtml(it, i) {
        var sit = SITUACOES[it.situacao];
        var numero;
        if (it.numero) {
            numero = '<span class="num">' + numeroHtml(it) + '</span>'
                + '<button type="button" class="copiar" aria-label="Copiar cartão" data-i="' + i + '">' + ICO_COPIAR + '</button>';
        } else {
            numero = '<div class="duo duo-motivo" title="' + esc(it.detalhe || '') + '"><strong>' + esc(it.motivo[0])
                + '</strong><span>' + esc(it.motivo[1]) + '</span></div>';
        }
        var testado = it.testado
            ? '<div class="duo"><strong>Testado por:</strong><span class="vulgo-nome">' + esc(it.testado) + '</span></div>'
            : (it.situacao === 'novo' ? '<span class="nulo">Primeiro registro</span>' : NULO);
        return '<tr data-situacao="' + it.situacao + '">'
            + '<td data-label="Número"><div class="cel-num"><span class="idx">' + it.linha + '</span>' + numero + '</div></td>'
            + '<td data-label="Status"><span class="selo ' + sit.tom + '">' + sit.rotulo + '</span></td>'
            + '<td data-label="Registro">' + (it.registro ? duo(it.registro, it.nota) : NULO) + '</td>'
            + '<td data-label="Testado por">' + testado + '</td>'
            + '<td data-label="Última consulta">' + (it.situacao === 'invalido' ? NULO : duo('Agora', estado.hora + ' UTC', estado.rotulo)) + '</td>'
            + '<td class="t-consultas" data-label="Consultas">'
            + (it.consultas !== undefined ? br(it.consultas) + '<span class="vezes">×</span>' : NULO) + '</td>'
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
        resCorpo.innerHTML = '<div class="tab-scroll"><table class="res-tab"><thead><tr>'
            + '<th class="c-numero">Número</th><th class="c-status">Status</th><th class="c-registro">Registro</th>'
            + '<th class="c-vulgo">Testado por</th><th class="c-consulta">Última consulta</th><th class="c-consultas">Consultas</th>'
            + '</tr></thead><tbody id="corpo"></tbody></table>'
            + '<div class="mais" id="mais">Carregando mais linhas…</div></div>';
        corpoTabela = $('corpo');
        sentinela = $('mais');
        estado.mostrados = 0;
        mostrarMais();
        if ('IntersectionObserver' in window) {
            observador = new IntersectionObserver(function (entradas) {
                if (entradas[0].isIntersecting && estado.mostrados < estado.lista.length) { mostrarMais(); }
            }, { rootMargin: '400px 0px' });
            observador.observe(sentinela);
        } else {
            while (estado.mostrados < estado.lista.length) { mostrarMais(); }
        }
    }

    function filtrar(alvo) {
        estado.lista = alvo === 'todos'
            ? estado.itens
            : estado.itens.filter(function (it) { return it.situacao === alvo; });
        Array.prototype.forEach.call(seg.children, function (b) {
            b.setAttribute('aria-pressed', b.dataset.alvo === alvo ? 'true' : 'false');
        });
        resSub.textContent = descrever(estado.lista.length);
        montarTabela();
    }

    function vazio(titulo, texto) {
        resFiltros.hidden = true;
        resCorpo.innerHTML = '<div class="vazio"><h3>' + esc(titulo) + '</h3><p>' + esc(texto) + '</p></div>';
    }

    function atualizarStats(stats) {
        if (!stats) { return; }
        Array.prototype.forEach.call(document.querySelectorAll('[data-stat]'), function (el) {
            var v = stats[el.dataset.stat];
            if (v === undefined || v === null) { return; }
            el.textContent = typeof v === 'number' ? br(v) : v;
        });
    }

    function renderizar(dados) {
        estado.itens = dados.itens;
        estado.hora = dados.agora_hora;
        estado.rotulo = dados.agora_rotulo;
        atualizarStats(dados.stats);
        var pn = $('pn-res');
        pn.classList.remove('surge');
        void pn.offsetWidth;
        pn.classList.add('surge');
        if (!estado.itens.length) {
            resSub.textContent = descrever(0);
            vazio('Nenhuma linha processada', 'O lote enviado não continha linhas utilizáveis.');
            return;
        }
        var totais = { todos: estado.itens.length };
        for (var k in dados.resumo) { totais[k] = dados.resumo[k]; }
        seg.innerHTML = FILTROS.map(function (f) {
            return '<button type="button" data-alvo="' + f[0] + '" aria-pressed="false"'
                + (totais[f[0]] ? '' : ' disabled') + '>' + f[1] + ' <b>' + br(totais[f[0]] || 0) + '</b></button>';
        }).join('');
        resFiltros.hidden = false;
        filtrar('todos');
    }

    seg.addEventListener('click', function (ev) {
        var botao = ev.target.closest('button[data-alvo]');
        if (botao && !botao.disabled) { filtrar(botao.dataset.alvo); }
    });

    resCorpo.addEventListener('click', function (ev) {
        var botao = ev.target.closest('.copiar');
        if (botao) {
            var it = estado.lista[+botao.dataset.i];
            if (!it) { return; }
            navigator.clipboard.writeText(textoCopia(it)).then(function () {
                botao.classList.add('feito');
                botao.innerHTML = CHECK;
                setTimeout(function () {
                    botao.classList.remove('feito');
                    botao.innerHTML = ICO_COPIAR;
                }, 1400);
            });
            return;
        }
        var linha = ev.target.closest('tbody tr');
        if (linha) { linha.classList.toggle('sel'); }
    });

    function esqueleto() {
        var larguras = [168, 144, 72, 156, 134];
        var html = '<div class="skel">';
        for (var i = 0; i < larguras.length; i++) {
            html += '<div class="skel-l">'
                + '<span class="skel-b" style="width:18px"></span>'
                + '<span class="skel-b" style="width:' + larguras[i] + 'px"></span>'
                + '<span class="skel-b" style="width:78px"></span>'
                + '<span class="skel-b" style="width:72px"></span>'
                + '<span class="skel-b" style="width:96px"></span>'
                + '<span class="skel-b" style="width:52px"></span>'
                + '</div>';
        }
        resFiltros.hidden = true;
        resCorpo.innerHTML = html + '</div>';
        resSub.textContent = 'Verificando…';
    }

    function ocupado(sim) {
        botaoEnviar.disabled = sim;
        botaoEnviar.innerHTML = sim
            ? '<svg class="girando" width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"'
              + ' stroke-width="2" stroke-linecap="round"><path d="M8 1.8a6.2 6.2 0 1 0 6.2 6.2"/></svg><span>Verificando…</span>'
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
        if (!window.fetch) { return; }
        ev.preventDefault();
        ocupado(true);
        alertar(null);
        esqueleto();
        fetch('/verificar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({
                csrf: form.elements.csrf.value,
                vulgo: form.elements.vulgo.value,
                numeros: campo.value
            })
        }).then(function (resp) {
            return resp.json().catch(function () { return {}; }).then(function (dados) {
                if (!resp.ok) { throw new Error(dados.detail || 'Falha ao verificar (HTTP ' + resp.status + ').'); }
                return dados;
            });
        }).then(function (dados) {
            renderizar(dados);
        }).catch(function (err) {
            alertar(err.message || 'Falha de conexão com o servidor.');
            resSub.textContent = 'Aguardando verificação';
            vazio('Verificação não concluída', 'Corrija o problema acima e tente novamente.');
        }).then(function () {
            ocupado(false);
        });
    });

    var inicial = $('dados-resultado');
    if (inicial) { renderizar(JSON.parse(inicial.textContent)); }
})();
