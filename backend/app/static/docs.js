(function () {
    'use strict';

    /* ---------------- realce de sintaxe ---------------- */
    var REGRAS = {
        json: /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\b\d+(?:\.\d+)?\b)/g,
        js: /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')(\s*:)?|\b(true|false|null|const|let|await|return|new)\b|(-?\b\d+(?:\.\d+)?\b)/g,
        py: /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')(\s*:)?|\b(True|False|None|import|from|for|in|def|return)\b|(-?\b\d+(?:\.\d+)?\b)/g,
        bash: /("(?:\\.|[^"\\])*"|'[^']*')()|\b(curl)\b|(\s-{1,2}[A-Za-z][\w-]*)/g
    };

    function escapar(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function realcar(texto, lang) {
        var re = REGRAS[lang];
        if (!re) { return escapar(texto); }
        re.lastIndex = 0;
        var saida = '', ultimo = 0, m;
        while ((m = re.exec(texto)) !== null) {
            if (m[0] === '') { re.lastIndex++; continue; }
            saida += escapar(texto.slice(ultimo, m.index));
            if (m[1] !== undefined) {
                saida += m[2]
                    ? '<span class="tk-p">' + escapar(m[1]) + '</span>' + escapar(m[2])
                    : '<span class="tk-s">' + escapar(m[1]) + '</span>';
            } else if (m[3] !== undefined) {
                saida += '<span class="tk-k">' + escapar(m[3]) + '</span>';
            } else if (m[4] !== undefined) {
                saida += '<span class="' + (lang === 'bash' ? 'tk-f' : 'tk-n') + '">' + escapar(m[4]) + '</span>';
            }
            ultimo = re.lastIndex;
        }
        return saida + escapar(texto.slice(ultimo));
    }

    Array.prototype.forEach.call(document.querySelectorAll('pre[data-lang]'), function (pre) {
        pre.innerHTML = realcar(pre.textContent, pre.dataset.lang);
    });

    /* ---------------- abas de linguagem ---------------- */
    Array.prototype.forEach.call(document.querySelectorAll('.bloco-abas'), function (abas) {
        var bloco = abas.closest('.bloco');
        var botoes = abas.querySelectorAll('button[data-aba]');
        Array.prototype.forEach.call(botoes, function (botao) {
            botao.addEventListener('click', function () {
                Array.prototype.forEach.call(botoes, function (outro) {
                    outro.setAttribute('aria-pressed', outro === botao ? 'true' : 'false');
                });
                Array.prototype.forEach.call(bloco.querySelectorAll('pre[data-painel]'), function (pre) {
                    pre.hidden = pre.dataset.painel !== botao.dataset.aba;
                });
            });
        });
    });

    /* ---------------- copiar ---------------- */
    var CHECK = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"'
        + ' stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="M2.8 8.6l3.1 3.1 7.3-7.4"/></svg>';

    document.addEventListener('click', function (ev) {
        var botao = ev.target.closest('.code-copiar');
        if (!botao) { return; }
        var texto = botao.dataset.copia;
        if (texto === undefined) {
            var bloco = botao.closest('.bloco');
            var pre = bloco && bloco.querySelector('pre:not([hidden])');
            texto = pre ? pre.textContent : '';
        }
        var original = botao.innerHTML;
        navigator.clipboard.writeText(texto).then(function () {
            botao.classList.add('feito');
            botao.innerHTML = CHECK;
            setTimeout(function () {
                botao.classList.remove('feito');
                botao.innerHTML = original;
            }, 1400);
        });
    });

    /* ---------------- índice: rola sem mudar a URL ---------------- */
    var links = Array.prototype.slice.call(document.querySelectorAll('.docs-indice a[href^="#"]'));

    function irPara(id, suave) {
        var alvo = document.getElementById(id);
        if (alvo) { alvo.scrollIntoView({ behavior: suave ? 'smooth' : 'auto', block: 'start' }); }
    }

    links.forEach(function (a) {
        a.addEventListener('click', function (ev) {
            ev.preventDefault();
            irPara(a.getAttribute('href').slice(1), true);
        });
    });

    if (location.hash) {
        var inicial = location.hash.slice(1);
        history.replaceState(null, '', location.pathname + location.search);
        irPara(inicial, false);
    }

    if (!links.length || !('IntersectionObserver' in window)) { return; }

    function marcar(id) {
        links.forEach(function (a) { a.classList.toggle('ativo', a.getAttribute('href') === '#' + id); });
    }

    var observador = new IntersectionObserver(function (entradas) {
        entradas.forEach(function (e) {
            if (e.isIntersecting) { marcar(e.target.id); }
        });
    }, { rootMargin: '-90px 0px -65% 0px' });

    links.forEach(function (a) {
        var alvo = document.getElementById(a.getAttribute('href').slice(1));
        if (alvo) { observador.observe(alvo); }
    });
})();
