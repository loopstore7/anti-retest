<?php

declare(strict_types=1);

require __DIR__ . '/AntiRetest.php';

session_start();
if (!isset($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

$dbPath = getenv('ANTIRETEST_DB') ?: dirname(__DIR__) . DIRECTORY_SEPARATOR . 'antiretest.db';
// Pasta dos txt diários; ANTIRETEST_LOG_DIR=- desliga a gravação em claro.
$logDirEnv = (string) (getenv('ANTIRETEST_LOG_DIR') ?: '');
$logDir = $logDirEnv === '-' ? null : ($logDirEnv !== '' ? $logDirEnv : DailyLog::defaultDirFor($dbPath));
$entrada = '';
$vulgo = '';
$resultado = null;
$erro = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        $erro = 'Sessão expirada. Recarregue a página e envie novamente.';
    } else {
        $vulgo = AntiRetest::sanitizeVulgo((string) ($_POST['vulgo'] ?? ''));
        $entrada = (string) ($_POST['numeros'] ?? '');
        $linhas = preg_split('/\r\n|\r|\n/', $entrada) ?: [];
        if ($vulgo === '') {
            $erro = 'Informe a Store (ou vulgo) antes de verificar.';
        } else {
            try {
                // Os novos entram no banco automaticamente e no txt do dia.
                $resultado = (new AntiRetest($dbPath, $logDir))->checkMany($linhas, true, $vulgo);
            } catch (Throwable $falha) {
                $erro = 'Falha ao acessar o banco: ' . $falha->getMessage();
            }
        }
    }
}

try {
    $stats = (new AntiRetest($dbPath))->stats();
} catch (Throwable $falha) {
    $stats = null;
    $erro = $erro ?? ('Falha ao abrir o banco: ' . $falha->getMessage());
}

// Consultas e repetidos vêm do banco (SUM(attempts) e retestes acumulados).
$exibeConsultas = $stats !== null ? (int) ($stats['attempts'] ?? 0) : 0;
$exibeRepetidos = $stats !== null ? (int) ($stats['repetidos'] ?? 0) : 0;

const MESES = ['jan', 'fev', 'mar', 'abr', 'mai', 'jun', 'jul', 'ago', 'set', 'out', 'nov', 'dez'];

function e(?string $valor): string
{
    return htmlspecialchars((string) $valor, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function n(int|float|null $valor): string
{
    return number_format((float) $valor, 0, ',', '.');
}

function dataCurta(?string $iso): string
{
    if ($iso === null || $iso === '') {
        return '—';
    }
    $data = DateTimeImmutable::createFromFormat('Y-m-d', substr($iso, 0, 10));
    if ($data === false) {
        return '—';
    }

    return $data->format('j') . ' ' . MESES[(int) $data->format('n') - 1] . ' ' . $data->format('Y');
}

/**
 * Motivo de inválido em duas linhas curtas para a tabela.
 *
 * @return array{0:string,1:string}
 */
function motivoCurto(string $motivo): array
{
    $m = mb_strtolower($motivo, 'UTF-8');
    if (str_contains($m, 'validade') || str_contains($m, 'cvv')) {
        return ['Linha incompleta', 'Falta validade ou CVV'];
    }
    if (str_contains($m, 'nenhum número')) {
        return ['Linha vazia', 'Nenhum número encontrado'];
    }
    if (str_contains($m, 'cartão válido') || str_contains($m, 'luhn') || str_contains($m, 'dígito')) {
        return ['Número inválido', 'PAN ou Luhn incorreto'];
    }

    return ['Linha inválida', 'Formato não reconhecido'];
}

/** Caracteres da máscara: BIN + ocultos + últimos 4 (15 na Amex, 16 nas outras). */
function numeroPartes(string $mascarado): array
{
    $ocultos = max(0, strlen($mascarado) - 10);

    return array_merge(
        str_split(substr($mascarado, 0, 6)),
        array_fill(0, $ocultos, '•'),
        str_split(substr($mascarado, 6 + $ocultos))
    );
}

/** Máscara agrupada de 4 em 4, com dígitos e ocultos estilizados separadamente. */
function numeroFormatado(string $mascarado): string
{
    $saida = '';
    foreach (numeroPartes($mascarado) as $i => $caractere) {
        if ($i > 0 && $i % 4 === 0) {
            $saida .= '<span class="nb-gap"></span>';
        }
        $saida .= $caractere === '•'
            ? '<span class="nb-mk">•</span>'
            : '<span class="nb-dg">' . e($caractere) . '</span>';
    }

    return $saida;
}

/** Mesma máscara em texto puro, para a ação de copiar. */
/** Exibe vulgo mascarado para quem testou antes (existente/repetido). */
function vulgoTestadoPor(?string $vulgo, string $situacao): ?string
{
    if (!in_array($situacao, ['existente', 'repetido'], true)) {
        return null;
    }
    $mascarado = AntiRetest::maskVulgo((string) ($vulgo ?? ''));
    if ($mascarado === '') {
        return null;
    }

    return $mascarado;
}

function numeroPlano(string $mascarado): string
{
    $saida = '';
    foreach (numeroPartes($mascarado) as $i => $caractere) {
        if ($i > 0 && $i % 4 === 0) {
            $saida .= ' ';
        }
        $saida .= $caractere;
    }

    return $saida;
}

/** PAN completo agrupado de 4 em 4. */
function numeroInteiro(string $digitos): string
{
    $saida = '';
    foreach (str_split($digitos) as $i => $caractere) {
        if ($i > 0 && $i % 4 === 0) {
            $saida .= '<span class="nb-gap"></span>';
        }
        $saida .= '<span class="nb-dg">' . e($caractere) . '</span>';
    }

    return $saida;
}

/** Cartão completo PAN|MM|AAAA|CVV com PAN agrupado de 4 em 4. */
function ccFullFormatado(string $ccFull): string
{
    $partes = explode('|', $ccFull, 4);
    if (count($partes) !== 4 || !ctype_digit($partes[0])) {
        return e($ccFull);
    }

    return numeroInteiro($partes[0])
        . '<span class="nb-sep">|</span><span class="nb-dg">' . e($partes[1]) . '</span>'
        . '<span class="nb-sep">|</span><span class="nb-dg">' . e($partes[2]) . '</span>'
        . '<span class="nb-sep">|</span><span class="nb-dg">' . e($partes[3]) . '</span>';
}

/** Assinatura do produto: losango externo + losango interno deslocado (repetição detectada). */
function marca(int $tamanho): string
{
    return '<svg class="marca-sim" width="' . $tamanho . '" height="' . $tamanho . '" viewBox="0 0 20 20"'
        . ' fill="none" aria-hidden="true">'
        . '<rect x="3.2" y="3.2" width="13.6" height="13.6" rx="3" transform="rotate(45 10 10)"'
        . ' stroke="currentColor" stroke-width="1.4" opacity=".55"/>'
        . '<rect x="6.8" y="6.8" width="6.4" height="6.4" rx="1.6" transform="rotate(45 10 10)"'
        . ' fill="currentColor"/>'
        . '</svg>';
}

// O motor grava em UTC; a consulta usa o mesmo fuso para as datas não divergirem.
$agora = new DateTimeImmutable('now', new DateTimeZone('UTC'));
$agoraRotulo = dataCurta($agora->format('Y-m-d')) . ', ' . $agora->format('H:i') . ' UTC';

$notaUltimo = '—';
if ($stats !== null && !empty($stats['last_day'])) {
    $ultimo = DateTimeImmutable::createFromFormat('Y-m-d', (string) $stats['last_day'], new DateTimeZone('UTC'));
    if ($ultimo !== false) {
        $dias = (int) $agora->setTime(0, 0)->diff($ultimo->setTime(0, 0))->days;
        $notaUltimo = $dias === 0 ? 'hoje' : 'há ' . n($dias) . ' dias';
    }
}

$situacoes = [
    'novo'      => ['rotulo' => 'Novo', 'tom' => 'ok'],
    'existente' => ['rotulo' => 'Existente', 'tom' => 'ambar'],
    'repetido'  => ['rotulo' => 'Repetido', 'tom' => 'indigo'],
    'invalido'  => ['rotulo' => 'Inválido', 'tom' => 'erro'],
];

// As quatro listas do motor viram uma tabela única, na ordem das linhas enviadas.
$registros = [];
if ($resultado !== null) {
    foreach ($resultado['new'] as $item) {
        $registros[] = [
            'linha' => (int) $item['line'],
            'numero' => (string) $item['masked'],
            'motivo' => null,
            'situacao' => 'novo',
            'registro' => null,
            'registro_nota' => null,
            'consultas' => (int) $item['attempts'],
            'vulgo' => (string) ($item['vulgo'] ?? ''),
            'cc_full' => (string) ($item['cc_full'] ?? ''),
        ];
    }
    foreach ($resultado['known'] as $item) {
        $dias = (int) $item['days_since_added'];
        $registros[] = [
            'linha' => (int) $item['line'],
            'numero' => (string) $item['masked'],
            'motivo' => null,
            'situacao' => 'existente',
            'registro' => dataCurta((string) $item['added_on']),
            'registro_nota' => $dias === 0
                ? 'Registrado hoje'
                : 'Registrado há ' . n($dias) . ($dias === 1 ? ' dia' : ' dias'),
            'consultas' => (int) $item['attempts'],
            'vulgo' => (string) ($item['vulgo'] ?? ''),
            'cc_full' => (string) ($item['cc_full'] ?? ''),
        ];
    }
    foreach ($resultado['duplicated'] as $item) {
        $registros[] = [
            'linha' => (int) $item['line'],
            'numero' => (string) $item['masked'],
            'motivo' => null,
            'situacao' => 'repetido',
            'registro' => 'Linha ' . (int) $item['first_line'],
            'registro_nota' => 'Duplicado no lote',
            'consultas' => null,
            'vulgo' => (string) ($item['vulgo'] ?? ''),
            'cc_full' => (string) ($item['cc_full'] ?? ''),
        ];
    }
    foreach ($resultado['invalid'] as $item) {
        $registros[] = [
            'linha' => (int) $item['line'],
            'numero' => null,
            'motivo' => (string) $item['reason'],
            'situacao' => 'invalido',
            'registro' => null,
            'registro_nota' => null,
            'consultas' => null,
            'vulgo' => null,
            'cc_full' => '',
        ];
    }
    usort($registros, static fn(array $a, array $b): int => $a['linha'] <=> $b['linha']);
}

$filtros = $resultado === null ? [] : [
    ['id' => 'todos', 'rotulo' => 'Todos', 'total' => count($registros)],
    ['id' => 'novo', 'rotulo' => 'Novos', 'total' => count($resultado['new'])],
    ['id' => 'existente', 'rotulo' => 'Existentes', 'total' => count($resultado['known'])],
    ['id' => 'repetido', 'rotulo' => 'Repetidos', 'total' => count($resultado['duplicated'])],
    ['id' => 'invalido', 'rotulo' => 'Inválidos', 'total' => count($resultado['invalid'])],
];

// Contagem inicial dos medidores, para o painel lateral já nascer coerente após um POST.
$linhasIniciais = $resultado !== null ? count($registros) : 0;
$validosIniciais = $resultado !== null
    ? count($resultado['new']) + count($resultado['known']) + count($resultado['duplicated'])
    : 0;
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>Anti Reteste V2 — Verificação de números</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20'><rect width='20' height='20' rx='5' fill='%234E63E6'/><rect x='4.6' y='4.6' width='10.8' height='10.8' rx='2.4' transform='rotate(45 10 10)' stroke='%23fff' stroke-width='1.3' fill='none' opacity='.6'/><rect x='7.4' y='7.4' width='5.2' height='5.2' rx='1.3' transform='rotate(45 10 10)' fill='%23fff'/></svg>">
<style>
/* ============================================================
   tokens
   ============================================================ */
:root {
    --bg:        #07090D;
    --sf:        #0D1016;
    --sf-alto:   #11151D;
    --sf-in:     #090C11;

    --bd:        rgba(255, 255, 255, .07);
    --bd-hi:     rgba(255, 255, 255, .12);
    --bd-soft:   rgba(255, 255, 255, .045);
    --topo:      rgba(255, 255, 255, .035);

    --t1: #F1F3F7;
    --t2: #B4BBC8;
    --t3: #8B93A3;
    --t4: #6B7382;

    --ac:     #4E63E6;
    --ac-hi:  #5D70F0;
    --ac-lo:  #4052C4;
    --ac-sf:  rgba(78, 99, 230, .13);
    --ac-ring: rgba(78, 99, 230, .3);

    --ok:     #2FBE84;
    --ok-cl:  #55D6A2;
    --aviso:  #DDA63C;
    --aviso-cl: #E9BE6E;
    --erro:   #E15155;
    --erro-cl: #F0868A;

    --sans: "Geist", Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --mono: "Geist Mono", "JetBrains Mono", ui-monospace, "Cascadia Mono", "SF Mono", Consolas, monospace;

    --lh: 22px;
    --pad-ed: 14px;

    --r: 11px;
    --r-md: 7px;
    --r-sm: 5px;

    --t: 150ms cubic-bezier(.4, 0, .2, 1);
    --ease: cubic-bezier(.4, 0, .2, 1);
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }

body {
    margin: 0;
    min-height: 100vh;
    min-height: 100dvh;
    background: var(--bg);
    color: var(--t1);
    font-family: var(--sans);
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    -webkit-tap-highlight-color: transparent;
    padding-bottom: env(safe-area-inset-bottom, 0);
}

/* grade de fundo — quase imperceptível */
.grade {
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    background-image:
        linear-gradient(rgba(255, 255, 255, .023) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, .023) 1px, transparent 1px);
    background-size: 52px 52px;
    mask-image: radial-gradient(ellipse 120% 90% at 50% 0%, #000 35%, transparent 100%);
    -webkit-mask-image: radial-gradient(ellipse 120% 90% at 50% 0%, #000 35%, transparent 100%);
}

::selection { background: rgba(78, 99, 230, .34); color: #fff; }

* { scrollbar-width: thin; scrollbar-color: rgba(255, 255, 255, .1) transparent; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, .09);
    border: 3px solid transparent;
    background-clip: content-box;
    border-radius: 6px;
}
::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, .18); background-clip: content-box; }
::-webkit-scrollbar-corner { background: transparent; }

/* ---------- primitivos ---------- */
.ponto { width: 6px; height: 6px; border-radius: 50%; background: var(--ok); flex: none; box-shadow: 0 0 0 3px rgba(47, 190, 132, .12); }
.ponto.off { background: var(--erro); box-shadow: 0 0 0 3px rgba(225, 81, 85, .12); }
.ponto.vivo { animation: respira 3.2s ease-in-out infinite; }
@keyframes respira { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }

.sinal { display: inline-flex; align-items: center; gap: 7px; font-size: 11.5px; color: var(--t2); white-space: nowrap; }

.micro {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--t3);
}
.micro svg { flex: none; color: var(--t3); }

.pilula {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 25px;
    padding: 0 11px;
    border: 1px solid var(--bd);
    border-radius: 999px;
    background: var(--sf-alto);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--t2);
    white-space: nowrap;
    transition: border-color var(--t);
}
.pilula:hover { border-color: var(--bd-hi); }
.pilula b { color: var(--t1); font-weight: 500; font-variant-numeric: tabular-nums; }

[data-tip] { position: relative; }
[data-tip]::after {
    content: attr(data-tip);
    position: absolute;
    top: calc(100% + 8px);
    left: 50%;
    transform: translate(-50%, -3px);
    padding: 5px 9px;
    background: var(--sf-alto);
    border: 1px solid var(--bd-hi);
    border-radius: var(--r-sm);
    color: var(--t2);
    font-size: 11px;
    font-weight: 400;
    letter-spacing: 0;
    text-transform: none;
    white-space: nowrap;
    opacity: 0;
    pointer-events: none;
    transition: opacity var(--t), transform var(--t);
    z-index: 80;
}
[data-tip]:hover::after { opacity: 1; transform: translate(-50%, 0); }
[data-tip-fim]::after { left: auto; right: 0; transform: translate(0, -3px); }
[data-tip-fim]:hover::after { transform: translate(0, 0); }

/* ============================================================
   topo
   ============================================================ */
.topo {
    position: sticky;
    top: 0;
    z-index: 60;
    height: 68px;
    background:
        linear-gradient(180deg, rgba(18, 22, 34, .97), rgba(7, 9, 13, .94)),
        radial-gradient(80% 140% at 0% 50%, rgba(78, 99, 230, .16), transparent 55%);
    backdrop-filter: blur(18px) saturate(160%);
    border-bottom: 1px solid var(--bd);
}
.topo-in {
    height: 100%;
    max-width: 1520px;
    margin: 0 auto;
    padding: 0 28px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.marca {
    display: flex;
    align-items: center;
    gap: 14px;
    min-width: 0;
}
.logo-sf {
    width: 42px;
    height: 42px;
    flex: none;
    display: grid;
    place-items: center;
    border-radius: 12px;
    background:
        radial-gradient(120% 120% at 22% 18%, rgba(255, 255, 255, .34), transparent 42%),
        linear-gradient(145deg, #7A8AFA 0%, #4E63E6 46%, #2F3FA8 100%);
    box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, .32),
        0 0 0 1px rgba(78, 99, 230, .4),
        0 10px 24px -12px rgba(78, 99, 230, .85);
    color: #fff;
}
.logo-txt { display: flex; flex-direction: column; gap: 3px; min-width: 0; line-height: 1.1; }
.logo-linha {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
}
.logo-nome {
    font-size: 18px;
    font-weight: 600;
    letter-spacing: -.04em;
    color: #fff;
}
.logo-v2 {
    display: inline-flex;
    align-items: center;
    height: 18px;
    padding: 0 7px;
    border-radius: 999px;
    background: rgba(78, 99, 230, .22);
    border: 1px solid rgba(93, 112, 240, .45);
    color: #C5CDFF;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: .08em;
    line-height: 1;
}
.logo-sub {
    font-size: 12px;
    font-weight: 500;
    letter-spacing: .01em;
    color: var(--t2);
}
.nav-sep {
    width: 1px;
    height: 28px;
    background: linear-gradient(180deg, transparent, var(--bd-hi), transparent);
    flex: none;
}
.nav-pagina {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 32px;
    padding: 0 13px;
    border: 1px solid var(--bd);
    border-radius: 999px;
    background: rgba(255, 255, 255, .035);
    color: var(--t1);
    font-size: 13px;
    font-weight: 500;
    letter-spacing: -.01em;
}
.nav-pagina i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--ac-hi);
    box-shadow: 0 0 0 3px rgba(78, 99, 230, .16);
    flex: none;
}
.barra-v { width: 1px; height: 15px; background: var(--bd); flex: none; }
.crumb { font-size: 12.5px; color: var(--t3); }
.crumb.atual { color: var(--t1); }

.topo-fim { margin-left: auto; display: flex; align-items: center; gap: 8px; }
.topo-total { font-size: 11.5px; color: var(--t3); font-variant-numeric: tabular-nums; white-space: nowrap; }

.topo-chip {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 30px;
    padding: 0 11px;
    border: 1px solid var(--bd);
    border-radius: 999px;
    background: linear-gradient(180deg, rgba(255, 255, 255, .04), rgba(255, 255, 255, .015));
    white-space: nowrap;
    transition: border-color var(--t), background var(--t);
}
.topo-chip:hover { border-color: var(--bd-hi); background: var(--sf-alto); }
.topo-chip.ok {
    border-color: rgba(47, 190, 132, .22);
    background: linear-gradient(180deg, rgba(47, 190, 132, .12), rgba(47, 190, 132, .04));
    color: var(--ok-cl);
}
.topo-chip.ok .sinal { color: var(--ok-cl); }
.topo-chip.off {
    border-color: rgba(225, 81, 85, .24);
    background: linear-gradient(180deg, rgba(225, 81, 85, .12), rgba(225, 81, 85, .04));
    color: var(--erro-cl);
}
.topo-chip.off .sinal { color: var(--erro-cl); }
.topo-chip .chip-n {
    font-size: 12.5px;
    font-weight: 500;
    letter-spacing: -.02em;
    color: var(--t1);
    font-variant-numeric: tabular-nums;
}
.topo-chip .chip-lab {
    font-size: 11px;
    font-weight: 500;
    letter-spacing: .04em;
    text-transform: uppercase;
    color: var(--t3);
}

.ico-btn {
    position: relative;
    width: 30px;
    height: 30px;
    display: grid;
    place-items: center;
    border: 1px solid var(--bd);
    border-radius: 999px;
    background: linear-gradient(180deg, rgba(255, 255, 255, .04), rgba(255, 255, 255, .015));
    color: var(--t2);
    cursor: pointer;
    transition: background var(--t), color var(--t), border-color var(--t);
}
.ico-btn:hover { background: var(--sf-alto); color: var(--t1); border-color: var(--bd-hi); }
.ico-btn[aria-expanded="true"] { background: var(--sf-alto); color: var(--t1); border-color: var(--bd-hi); }
.ico-btn .selo-n {
    position: absolute;
    top: 5px;
    right: 6px;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--ac);
    box-shadow: 0 0 0 2px var(--bg);
}

.pop-wrap { position: relative; }
.pop {
    position: absolute;
    top: 36px;
    right: 0;
    width: 300px;
    background: var(--sf-alto);
    border: 1px solid var(--bd-hi);
    border-radius: var(--r);
    box-shadow: inset 0 1px 0 var(--topo), 0 20px 48px -18px rgba(0, 0, 0, .95);
    padding: 6px;
    animation: cai 140ms cubic-bezier(.4, 0, .2, 1);
    z-index: 70;
}
.pop[hidden] { display: none; }
@keyframes cai { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; transform: none; } }
.pop-tit { padding: 8px 10px 7px; }
.pop-div { height: 1px; background: var(--bd-soft); margin: 6px 0; }
.aviso-item { display: flex; gap: 9px; padding: 8px 10px; border-radius: var(--r-sm); transition: background var(--t); }
.aviso-item:hover { background: rgba(255, 255, 255, .025); }
.aviso-item i { margin-top: 5px; }
.aviso-item strong { display: block; font-size: 12px; font-weight: 500; color: var(--t1); }
.aviso-item span { display: block; font-size: 11.5px; color: var(--t3); margin-top: 1px; }

/* ============================================================
   shell
   ============================================================ */
.app { position: relative; z-index: 1; display: flex; flex-direction: column; max-width: 1520px; margin: 0 auto; padding: 18px 28px 64px; }

.painel {
    background: var(--sf);
    border: 1px solid var(--bd);
    border-radius: var(--r);
    box-shadow: inset 0 1px 0 var(--topo);
    transition: border-color var(--t);
    min-width: 0;
}
.painel:hover { border-color: var(--bd-hi); }

.p-head {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 18px;
    min-width: 0;
}
.p-head-ico {
    width: 28px;
    height: 28px;
    flex: none;
    display: grid;
    place-items: center;
    border: 1px solid var(--bd);
    border-radius: var(--r-md);
    background: var(--sf-alto);
    color: var(--t2);
}
.p-head h2 { font-size: 13px; font-weight: 500; margin: 0; letter-spacing: -.008em; }
.p-head p { margin: 2px 0 0; font-size: 12.5px; color: var(--t3); }
.p-head-fim { margin-left: auto; display: flex; align-items: center; gap: 12px; flex: 0 1 auto; min-width: 0; }
.p-div { height: 1px; background: var(--bd-soft); }

/* ============================================================
   hero
   ============================================================ */
.hero { margin-bottom: 16px; overflow: hidden; }
.hero-topo {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    padding: 14px 20px;
}
.hero-corpo {
    position: relative;
    display: flex;
    align-items: flex-start;
    gap: 18px;
    padding: 8px 20px 22px;
}
.hero-corpo::before {
    content: "";
    position: absolute;
    inset: -40% auto auto -8%;
    width: 280px;
    height: 280px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(78, 99, 230, .16), transparent 68%);
    pointer-events: none;
}
.hero-sim {
    position: relative;
    width: 54px;
    height: 54px;
    flex: none;
    display: grid;
    place-items: center;
    border: 1px solid rgba(78, 99, 230, .35);
    border-radius: 14px;
    background:
        radial-gradient(120% 120% at 30% 20%, rgba(255, 255, 255, .12), transparent 50%),
        linear-gradient(180deg, rgba(78, 99, 230, .22), rgba(78, 99, 230, .06));
    color: var(--ac-hi);
    box-shadow: 0 10px 28px -16px rgba(78, 99, 230, .7);
}
.hero-txt { position: relative; min-width: 0; }
.hero-marca {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
}
.hero-marca b {
    font-size: 12px;
    font-weight: 600;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--ac-hi);
}
.hero-marca span {
    display: inline-flex;
    align-items: center;
    height: 18px;
    padding: 0 7px;
    border-radius: 999px;
    background: rgba(78, 99, 230, .18);
    border: 1px solid rgba(93, 112, 240, .4);
    color: #C5CDFF;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: .08em;
}
.hero-txt h1 { font-size: 28px; font-weight: 600; letter-spacing: -.038em; line-height: 1.12; margin: 0 0 7px; }
.hero-txt p { margin: 0; font-size: 14px; color: var(--t2); max-width: 74ch; }
.hero-pe { display: grid; grid-template-columns: repeat(4, 1fr); border-top: 1px solid var(--bd-soft); }
.hp { padding: 14px 20px; border-left: 1px solid var(--bd-soft); min-width: 0; transition: background var(--t); }
.hp:first-child { border-left: 0; }
.hp:hover { background: rgba(255, 255, 255, .012); }
.hp-val {
    display: block;
    font-size: 19px;
    font-weight: 500;
    letter-spacing: -.028em;
    font-variant-numeric: tabular-nums;
    line-height: 1.2;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.hp-lab { display: block; margin-top: 5px; font-size: 12.5px; color: var(--t2); }

/* ============================================================
   colunas
   ============================================================ */
.colunas { display: grid; grid-template-columns: minmax(0, 1fr) 348px; gap: 16px; margin-bottom: 16px; align-items: start; }

/* ---------- editor ---------- */
.ed-wrap { padding: 0 18px 16px; }
.vulgo-campo {
    display: flex;
    flex-direction: column;
    gap: 7px;
    margin-bottom: 12px;
}
.vulgo-campo label {
    font-size: 11px;
    font-weight: 500;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--t3);
}
.vulgo-campo input {
    height: 38px;
    padding: 0 13px;
    border: 1px solid var(--bd);
    border-radius: var(--r-md);
    background: var(--sf-in);
    color: var(--t1);
    font-family: inherit;
    font-size: 13px;
    outline: 0;
    transition: border-color var(--t);
}
.vulgo-campo input::placeholder { color: var(--t4); }
.vulgo-campo input:focus { border-color: rgba(78, 99, 230, .35); }
.editor {
    background: var(--sf-in);
    border: 1px solid var(--bd);
    border-radius: var(--r-md);
    overflow: hidden;
    transition: border-color var(--t);
}
.editor.focado { border-color: rgba(78, 99, 230, .35); }
.ed-bar {
    display: flex;
    align-items: center;
    height: 31px;
    padding: 0 13px;
    border-bottom: 1px solid var(--bd-soft);
    background: rgba(255, 255, 255, .014);
}
.ed-rot { display: flex; align-items: center; gap: 8px; font-size: 11px; font-weight: 500; letter-spacing: .1em; text-transform: uppercase; color: var(--t3); transition: color var(--t); }
.editor.focado .ed-rot { color: var(--t2); }
.ed-tick { width: 2px; height: 9px; border-radius: 1px; background: var(--t3); transition: background var(--t), height var(--t); }
.editor.focado .ed-tick { background: var(--ac); height: 11px; }
.ed-meta { margin-left: auto; font-family: var(--mono); font-size: 11px; letter-spacing: .06em; color: var(--t3); }

.ed-corpo { position: relative; display: flex; height: 312px; overflow: hidden; }
.linha-ativa { position: absolute; left: 0; right: 0; top: var(--pad-ed); height: var(--lh); pointer-events: none; opacity: 0; transition: opacity var(--t); z-index: 0; }
.editor.focado .linha-ativa { opacity: 1; }
.linha-ativa::before { content: ""; position: absolute; inset: 0; background: rgba(255, 255, 255, .022); }
.linha-ativa::after { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--ac); }

.gutter {
    position: relative;
    z-index: 1;
    flex: none;
    width: 50px;
    height: 100%;
    padding: var(--pad-ed) 12px var(--pad-ed) 0;
    overflow: hidden;
    text-align: right;
    border-right: 1px solid var(--bd-soft);
    font-family: var(--mono);
    font-size: 11px;
    line-height: var(--lh);
    color: var(--t4);
    user-select: none;
    -webkit-user-select: none;
}
.gutter span { display: block; font-variant-numeric: tabular-nums; }

.campo { position: relative; z-index: 1; flex: 1; min-width: 0; height: 100%; }
.realce, .campo textarea {
    margin: 0;
    padding: var(--pad-ed) 18px;
    font-family: var(--mono);
    font-size: 12.5px;
    font-weight: 400;
    line-height: var(--lh);
    letter-spacing: .015em;
    white-space: pre;
    tab-size: 4;
}
.realce { position: absolute; inset: 0; overflow: hidden; pointer-events: none; color: var(--t3); }
.realce b { color: var(--t1); font-weight: 500; }
.realce i { color: var(--t3); font-style: normal; }
.realce s { color: var(--t4); text-decoration: none; }
.campo textarea {
    position: relative;
    display: block;
    width: 100%;
    height: 100%;
    border: 0;
    outline: 0;
    resize: none;
    background: none;
    color: transparent;
    caret-color: var(--ac-hi);
    overflow: auto;
}
.campo textarea::selection { background: rgba(78, 99, 230, .32); }
.campo textarea::placeholder { color: var(--t4); }
.editor.sem-realce .realce { display: none; }
.editor.sem-realce textarea { color: var(--t2); }

/* ---------- rodapé da entrada ---------- */
.ed-pe { display: flex; align-items: center; gap: 14px; padding: 12px 18px; border-top: 1px solid var(--bd-soft); min-width: 0; }
.medidores { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; min-width: 0; }
.med { display: inline-flex; align-items: baseline; gap: 6px; font-size: 11px; font-weight: 500; letter-spacing: .08em; text-transform: uppercase; color: var(--t3); white-space: nowrap; }
.med b { font-size: 12.5px; font-weight: 500; letter-spacing: 0; color: var(--t1); font-variant-numeric: tabular-nums; }
.med-pt { width: 3px; height: 3px; border-radius: 50%; background: var(--t4); flex: none; }
.pe-fim { margin-left: auto; display: flex; align-items: center; gap: 8px; flex: 0 1 auto; min-width: 0; }

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    height: 36px;
    padding: 0 16px;
    border: 1px solid transparent;
    border-radius: var(--r-md);
    font-family: inherit;
    font-size: 12.5px;
    font-weight: 500;
    line-height: 1;
    cursor: pointer;
    white-space: nowrap;
    transition: background var(--t), border-color var(--t), color var(--t);
}
.btn:focus-visible { outline: 0; box-shadow: 0 0 0 3px var(--ac-ring); }
.btn:active { transform: translateY(1px); }
.btn-pri { background: var(--ac); color: #fff; box-shadow: inset 0 1px 0 rgba(255, 255, 255, .16); }
.btn-pri:hover { background: var(--ac-hi); }
.btn-pri:active { background: var(--ac-lo); }
.btn-pri:disabled { background: var(--sf-alto); color: var(--t3); cursor: default; box-shadow: none; transform: none; }
.btn-pri .seta { transition: transform var(--t); opacity: .85; }
.btn-pri:hover:not(:disabled) .seta { transform: translateX(2px); }
.btn-gh { background: none; border-color: var(--bd); color: var(--t2); }
.btn-gh:hover { background: var(--sf-alto); border-color: var(--bd-hi); color: var(--t1); }

.girando { animation: gira 650ms linear infinite; }
@keyframes gira { to { transform: rotate(360deg); } }

/* ============================================================
   lateral
   ============================================================ */
.lateral .p-head { padding-bottom: 12px; }
.lt-bloco { padding: 13px 18px; border-top: 1px solid var(--bd-soft); }
.lt-status { display: flex; align-items: center; gap: 8px; padding: 0 18px 14px; font-size: 12.5px; color: var(--t2); }
.lt-val { display: block; font-size: 24px; font-weight: 500; letter-spacing: -.03em; font-variant-numeric: tabular-nums; line-height: 1.15; margin-top: 8px; }
.lt-sub { display: block; font-size: 12.5px; color: var(--t2); margin-top: 4px; }

.lt-par { display: grid; grid-template-columns: 1fr 1fr; }
.lt-cel { padding: 13px 18px; border-top: 1px solid var(--bd-soft); }
.lt-cel + .lt-cel { border-left: 1px solid var(--bd-soft); }
.lt-cel .lt-val { font-size: 19px; margin-top: 7px; }
.lt-cel.ok .lt-val { color: var(--ok-cl); }
.lt-cel.av .lt-val { color: var(--aviso); }

.barra { display: flex; gap: 2px; height: 3px; margin-top: 11px; background: rgba(255, 255, 255, .055); border-radius: 2px; overflow: hidden; }
.barra i { display: block; height: 100%; width: 0; transition: width 250ms cubic-bezier(.4, 0, .2, 1); }
.barra .b-ok { background: var(--ok); }
.barra .b-av { background: var(--aviso); }

.lt-pe { display: flex; align-items: center; gap: 9px; padding: 12px 18px; border-top: 1px solid var(--bd-soft); }
.lt-pe-txt strong { display: block; font-size: 12.5px; font-weight: 500; color: var(--t1); }
.lt-pe-txt span { display: block; font-size: 12px; color: var(--t3); margin-top: 2px; }

/* ============================================================
   resultados
   ============================================================ */
/* segmented control */
.seg {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 3px;
    border: 1px solid var(--bd);
    border-radius: var(--r-md);
    background: var(--sf-in);
    min-width: 0;
    max-width: 100%;
}
.seg button {
    display: inline-flex;
    align-items: baseline;
    gap: 6px;
    height: 26px;
    padding: 0 10px;
    border: 1px solid transparent;
    border-radius: var(--r-sm);
    background: none;
    font-family: inherit;
    font-size: 12px;
    line-height: 26px;
    color: var(--t3);
    cursor: pointer;
    white-space: nowrap;
    transition: background 140ms var(--ease), color 140ms var(--ease), border-color 140ms var(--ease);
}
.seg button:hover:not(:disabled):not([aria-pressed="true"]) { color: var(--t2); background: rgba(255, 255, 255, .03); }
.seg button[aria-pressed="true"] { background: var(--sf-alto); border-color: var(--bd); color: var(--t1); }
.seg button:disabled { color: var(--t4); cursor: default; }
.seg button:focus-visible { outline: 0; border-color: var(--ac-ring); }
.seg b { font-weight: 400; font-size: 12px; color: var(--t3); font-variant-numeric: tabular-nums; }
.seg button[aria-pressed="true"] b { color: var(--t2); }

.tab-scroll { max-width: 100%; overflow-x: auto; border-radius: 0 0 var(--r) var(--r); }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }

thead th {
    position: sticky;
    top: 0;
    z-index: 1;
    height: 36px;
    background: var(--sf);
    text-align: left;
    padding: 0 18px;
    font-size: 11.5px;
    font-weight: 500;
    letter-spacing: .05em;
    text-transform: uppercase;
    color: var(--t3);
    border-top: 1px solid var(--bd-soft);
    border-bottom: 1px solid var(--bd-soft);
    white-space: nowrap;
}

tbody td {
    height: 52px;
    padding: 0 18px;
    border-bottom: 1px solid rgba(255, 255, 255, .035);
    font-size: 13px;
    color: var(--t2);
    vertical-align: middle;
    transition: background 140ms var(--ease);
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: rgba(255, 255, 255, .026); }
tbody tr.sel td { background: rgba(78, 99, 230, .06); }
tbody tr.sel td:first-child { box-shadow: inset 2px 0 0 var(--ac); }

.c-numero { width: 32%; }
.c-status { width: 14%; }
.c-registro { width: 18%; }
.c-vulgo { width: 14%; }
.c-consulta { width: 14%; }
.c-consultas { width: 8%; text-align: right; }

/* número: informação principal da linha */
.cel-num { display: flex; align-items: center; gap: 13px; min-width: 0; }
.idx {
    flex: none;
    width: 18px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--t3);
    font-variant-numeric: tabular-nums;
    text-align: right;
}
.num {
    font-family: var(--mono);
    font-size: 13.5px;
    font-weight: 500;
    letter-spacing: .03em;
    color: var(--t1);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    transition: color 140ms var(--ease);
}
tbody tr:hover .num, tbody tr.sel .num { color: #fff; }
/* largura fixa de 1ch: o bullet costuma faltar na fonte mono e cairia em fallback */
.nb-dg, .nb-mk { display: inline-block; width: 1ch; text-align: center; }
.nb-dg { color: inherit; }
.nb-mk { color: #4E5766; }
.nb-gap { display: inline-block; width: .7ch; }
.nb-sep { color: var(--t4); margin: 0 .15ch; }
.motivo { min-width: 0; color: var(--t3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.duo-motivo strong { color: var(--t1); font-weight: 500; }
.duo-motivo span { color: var(--t3); }

.copiar {
    flex: none;
    width: 24px;
    height: 24px;
    display: grid;
    place-items: center;
    border: 1px solid transparent;
    border-radius: var(--r-sm);
    background: none;
    color: var(--t4);
    cursor: pointer;
    opacity: 0;
    transition: opacity 140ms var(--ease), color 140ms var(--ease), background 140ms var(--ease), border-color 140ms var(--ease);
}
tbody tr:hover .copiar, .copiar:focus-visible { opacity: 1; }
.copiar:hover { color: var(--t1); background: var(--sf-alto); border-color: var(--bd); }
.copiar:focus-visible { outline: 0; border-color: var(--ac-ring); }
.copiar.feito { opacity: 1; color: var(--ok-cl); }

/* status: ponto colorido + label legível */
.selo { display: inline-flex; align-items: center; gap: 9px; font-size: 13px; color: var(--t1); white-space: nowrap; }
.selo::before { content: ""; width: 6px; height: 6px; border-radius: 50%; flex: none; }
.selo.ok::before { background: var(--ok); box-shadow: 0 0 0 3px rgba(47, 190, 132, .14); }
.selo.ambar::before { background: var(--aviso); box-shadow: 0 0 0 3px rgba(221, 166, 60, .14); }
.selo.indigo::before { background: var(--ac-hi); box-shadow: 0 0 0 3px rgba(78, 99, 230, .16); }
.selo.erro::before { background: var(--erro); box-shadow: 0 0 0 3px rgba(225, 81, 85, .14); }

/* dado + metadado */
.duo strong { display: block; font-size: 13px; font-weight: 400; color: var(--t2); line-height: 1.3; font-variant-numeric: tabular-nums; }
.duo span { display: block; margin-top: 2px; font-size: 12.5px; color: var(--t3); line-height: 1.3; }
.vulgo-nome { display: block; font-size: 13px; font-weight: 500; color: var(--t1); line-height: 1.3; }
td.t-consultas { text-align: right; font-family: var(--mono); font-size: 13px; color: var(--t2); font-variant-numeric: tabular-nums; }
.vezes { color: var(--t3); font-size: 12px; }
.nulo { color: var(--t3); }

.vazio { padding: 34px 18px 38px; text-align: center; border-top: 1px solid var(--bd-soft); }
.vazio-sim {
    width: 38px;
    height: 38px;
    margin: 0 auto 12px;
    display: grid;
    place-items: center;
    border: 1px solid var(--bd);
    border-radius: var(--r-md);
    background: var(--sf-alto);
    color: var(--t3);
}
.vazio h3 { margin: 0 0 3px; font-size: 12.5px; font-weight: 500; color: var(--t2); }
.vazio p { margin: 0; font-size: 12.5px; color: var(--t3); }

/* skeleton durante a consulta */
.skel { padding: 4px 0 6px; border-top: 1px solid var(--bd-soft); }
.skel-l { display: flex; align-items: center; gap: 18px; padding: 11px 18px; }
.skel-b { height: 9px; border-radius: 3px; background: linear-gradient(90deg, rgba(255,255,255,.04) 25%, rgba(255,255,255,.085) 37%, rgba(255,255,255,.04) 63%); background-size: 400% 100%; animation: brilha 1.3s ease infinite; }
@keyframes brilha { from { background-position: 100% 50%; } to { background-position: 0 50%; } }

.alerta { display: flex; gap: 11px; align-items: flex-start; background: rgba(225, 81, 85, .06); border: 1px solid rgba(225, 81, 85, .22); border-radius: var(--r-md); padding: 11px 14px; margin-bottom: 16px; font-size: 12.5px; }
.alerta svg { flex: none; margin-top: 2px; color: var(--erro); }

.surge { animation: surge 200ms cubic-bezier(.4, 0, .2, 1); }
@keyframes surge { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: none; } }

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: 1ms !important; animation-iteration-count: 1 !important; transition-duration: 1ms !important; }
}

/* ============================================================
   tela cheia: a página não rola, o scroll mora na tabela
   ============================================================ */
@media (min-width: 1181px) and (min-height: 700px) {
    html, body { height: 100%; }
    body { display: flex; flex-direction: column; }
    .topo { flex: none; }
    /* width explícito: como flex item, o margin auto encolheria o container */
    .app { flex: 1; width: 100%; min-height: 0; padding-bottom: 16px; }

    .colunas { flex: none; }

    /* hero e lateral cedem respiro para sobrar altura à tabela */
    .hero-topo { padding: 11px 20px; }
    .hero-corpo { padding: 4px 20px 15px; }
    .hero-txt h1 { font-size: 24px; }
    .hero-sim { width: 46px; height: 46px; }
    .hp { padding: 11px 20px; }

    .lateral .p-head { padding: 12px 18px 9px; }
    .lt-status { padding: 0 18px 10px; }
    .lt-bloco, .lt-cel { padding: 10px 18px; }
    .lt-val { font-size: 21px; margin-top: 5px; }
    .lt-cel .lt-val { font-size: 18px; margin-top: 5px; }
    .barra { margin-top: 9px; }
    .lt-pe { padding: 10px 18px; }

    /* altura ligada à viewport: o editor não cresce com o conteúdo */
    .ed-corpo { height: clamp(126px, 18vh, 300px); }

    #pn-res { flex: 1; min-height: 170px; display: flex; flex-direction: column; }
    #pn-res > .p-head { flex: none; }
    #res-corpo { flex: 1; min-height: 0; display: flex; flex-direction: column; }
    .tab-scroll { flex: 1; min-height: 0; overflow: auto; }
    .vazio { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px 18px; }
}

/* ============================================================
   responsivo
   ============================================================ */
@media (max-width: 1180px) {
    .colunas { grid-template-columns: minmax(0, 1fr); }
    .lateral .lt-par { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 860px) {
    .hero-pe { grid-template-columns: repeat(2, 1fr); }
    .hp:nth-child(3), .hp:nth-child(4) { border-top: 1px solid var(--bd-soft); }
    .hp:nth-child(2n+1) { border-left: 0; }
    .topo-fim .topo-chip:nth-child(3),
    .topo-fim .topo-chip:nth-child(4) { display: none; }
}

@media (max-width: 720px) {
    .topo {
        height: auto;
        min-height: 56px;
    }
    .topo-in {
        flex-wrap: wrap;
        align-items: center;
        gap: 10px 12px;
        padding: 10px max(14px, env(safe-area-inset-left, 14px)) 10px max(14px, env(safe-area-inset-right, 14px));
        height: auto;
        min-height: 56px;
    }
    .app {
        padding: 14px max(14px, env(safe-area-inset-left, 14px)) max(40px, calc(24px + env(safe-area-inset-bottom, 0)));
    }
    .barra-v, .nav-sep, .nav-pagina { display: none; }
    .marca { flex: 1 1 auto; min-width: 0; }
    .logo-nome { font-size: 16px; }
    .logo-sf { width: 36px; height: 36px; border-radius: 10px; }
    .topo-fim {
        margin-left: 0;
        flex: 1 1 100%;
        justify-content: flex-start;
        flex-wrap: nowrap;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
        padding-bottom: 2px;
        mask-image: linear-gradient(90deg, #000 92%, transparent);
        -webkit-mask-image: linear-gradient(90deg, #000 92%, transparent);
    }
    .topo-fim::-webkit-scrollbar { display: none; }
    .topo-fim .topo-chip { display: inline-flex; flex: none; }
    .topo-fim .pop-wrap { flex: none; margin-left: auto; }
    .hero { margin-bottom: 12px; }
    .hero-topo, .hero-corpo, .ed-wrap, .ed-pe, .p-head,
    .lt-bloco, .lt-cel, .lt-pe, .lt-status { padding-left: 14px; padding-right: 14px; }
    .hero-topo { padding-top: 12px; padding-bottom: 12px; }
    .hero-corpo { padding-top: 0; padding-bottom: 16px; gap: 12px; }
    .hero-txt h1 { font-size: 20px; line-height: 1.2; }
    .hero-txt p { font-size: 13px; }
    .hero-sim { width: 40px; height: 40px; border-radius: 11px; }
    .hero-pe { grid-template-columns: repeat(2, 1fr); }
    .hp { padding: 12px 14px; }
    .hp-val { font-size: 18px; }
    .p-head { flex-wrap: wrap; gap: 10px; padding-top: 12px; padding-bottom: 12px; }
    .p-head-fim { margin-left: 0; flex: 1 1 100%; flex-wrap: wrap; }
    .p-head > div > p { font-size: 12px; line-height: 1.45; }
    .seg {
        overflow-x: auto;
        flex: 1 1 auto;
        width: 100%;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
    }
    .seg::-webkit-scrollbar { display: none; }
    .seg button {
        min-height: 36px;
        padding: 0 12px;
        flex: none;
    }
    .ed-corpo { height: clamp(180px, 38vh, 280px); min-height: 180px; }
    .ed-pe { flex-wrap: wrap; gap: 12px; padding-top: 10px; padding-bottom: 10px; }
    .pe-fim { margin-left: 0; flex: 1 1 100%; width: 100%; }
    .pe-fim .btn { flex: 1; min-height: 44px; }
    .gutter { width: 36px; padding-right: 8px; font-size: 10px; }
    .realce, .campo textarea { padding-left: 12px; padding-right: 12px; font-size: 12px; }
    .ed-meta { display: none; }
    .vulgo-campo input { min-height: 44px; font-size: 16px; }
    .skel-l { gap: 12px; }
    .pop {
        position: fixed;
        top: auto;
        right: max(10px, env(safe-area-inset-right, 10px));
        left: max(10px, env(safe-area-inset-left, 10px));
        bottom: max(10px, env(safe-area-inset-bottom, 10px));
        width: auto;
        max-height: min(70vh, 520px);
        overflow-y: auto;
        border-radius: var(--r);
    }
    .copiar {
        opacity: 1;
        width: 32px;
        height: 32px;
    }
    .cel-num {
        flex-wrap: nowrap;
        align-items: center;
        gap: 8px;
        width: 100%;
    }
    .num {
        flex: 1;
        min-width: 0;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        font-size: 12px;
        scrollbar-width: none;
    }
    .num::-webkit-scrollbar { display: none; }
    [data-tip]::after { display: none; }

    /* tabela vira cards empilhados */
    .tab-scroll { overflow: visible; border-radius: 0 0 var(--r) var(--r); }
    .res-tab { table-layout: auto; }
    .res-tab thead { display: none; }
    .res-tab tbody tr {
        display: block;
        padding: 12px 14px;
        border-bottom: 1px solid rgba(255, 255, 255, .035);
    }
    .res-tab tbody tr:last-child { border-bottom: 0; }
    .res-tab tbody tr:hover td,
    .res-tab tbody tr.sel td { background: none; }
    .res-tab tbody tr.sel {
        background: rgba(78, 99, 230, .06);
        box-shadow: inset 3px 0 0 var(--ac);
    }
    .res-tab tbody td {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 12px;
        height: auto;
        min-height: 0;
        padding: 7px 0;
        border-bottom: none;
    }
    .res-tab tbody td::before {
        content: attr(data-label);
        flex: none;
        width: 34%;
        max-width: 120px;
        padding-top: 1px;
        font-size: 10.5px;
        font-weight: 500;
        letter-spacing: .06em;
        text-transform: uppercase;
        color: var(--t3);
        line-height: 1.35;
    }
    .res-tab tbody td:not(:first-child) > * { flex: 1; min-width: 0; text-align: right; }
    .res-tab tbody td:first-child {
        display: block;
        padding: 0 0 10px;
        margin-bottom: 4px;
        border-bottom: 1px solid var(--bd-soft);
    }
    .res-tab tbody td:first-child::before { display: none; }
    .res-tab tbody td:first-child > * { text-align: left; }
    .res-tab tbody td:first-child .cel-num { justify-content: flex-start; }
    .res-tab tbody td.t-consultas {
        text-align: right;
        justify-content: space-between;
    }
    .res-tab tbody td.t-consultas::before { padding-top: 2px; }
    .res-tab .duo strong,
    .res-tab .duo span,
    .res-tab .selo,
    .res-tab .nulo,
    .res-tab .vulgo-nome { text-align: right; }
    .res-tab .duo-motivo { text-align: left; }
}

@media (max-width: 480px) {
    .logo-sub { display: none; }
    .hero-topo .pilula:last-child { display: none; }
    .hero-corpo { flex-direction: column; align-items: stretch; }
    .hero-sim { align-self: flex-start; }
    .hero-pe { grid-template-columns: 1fr 1fr; }
    .hp-lab { font-size: 11px; }
    .p-head > div > p { display: none; }
    .p-head-fim .micro { width: 100%; }
    .medidores { width: 100%; justify-content: space-between; }
    .med-pt { display: none; }
    .lt-val { font-size: 20px; }
    .res-tab tbody td::before { width: 38%; max-width: 108px; }
    .nb-gap { width: .45ch; }
}

@media (hover: none) and (pointer: coarse) {
    .copiar { opacity: 1; }
    .ico-btn, .btn, .seg button { min-height: 44px; min-width: 44px; }
    .seg button { min-width: auto; padding: 0 14px; }
    tbody tr:hover td { background: none; }
}
</style>
</head>
<body>

<div class="grade" aria-hidden="true"></div>

<header class="topo">
    <div class="topo-in">
        <div class="marca">
            <span class="logo-sf"><?= marca(20) ?></span>
            <span class="logo-txt">
                <span class="logo-linha">
                    <span class="logo-nome">Anti Reteste</span>
                    <span class="logo-v2">V2</span>
                </span>
                <span class="logo-sub">Verificação de números em lote</span>
            </span>
        </div>
        <i class="nav-sep" aria-hidden="true"></i>
        <span class="nav-pagina"><i></i>Verificação</span>

        <div class="topo-fim">
            <span class="topo-chip<?= $stats === null ? ' off' : ' ok' ?>"
                  data-tip="<?= $stats === null ? 'Sem resposta do banco de dados' : 'Todos os serviços funcionando normalmente' ?>">
                <span class="sinal">
                    <i class="ponto<?= $stats === null ? ' off' : ' vivo' ?>"></i>
                    <?= $stats === null ? 'Indisponível' : 'Operacional' ?>
                </span>
            </span>
            <span class="topo-chip" data-tip="Total de registros na base">
                <b class="chip-n"><?= $stats !== null ? n((int) $stats['total']) : '—' ?></b>
                <span class="chip-lab">registros</span>
            </span>
            <?php if ($stats !== null): ?>
                <span class="topo-chip" data-tip="Total de consultas registradas na base">
                    <b class="chip-n"><?= n($exibeConsultas) ?></b>
                    <span class="chip-lab">consultas</span>
                </span>
                <span class="topo-chip" data-tip="Retestes — registro já existente consultado de novo">
                    <b class="chip-n"><?= n($exibeRepetidos) ?></b>
                    <span class="chip-lab">repetidos</span>
                </span>
            <?php endif; ?>

            <div class="pop-wrap">
                <button type="button" class="ico-btn" id="bt-avisos" aria-expanded="false" aria-controls="pop-avisos" aria-label="Avisos" data-tip="Avisos do sistema">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8.5a6 6 0 1 0-12 0c0 6-2.5 7.5-2.5 7.5h17S18 14.5 18 8.5"/><path d="M13.7 19.5a2 2 0 0 1-3.4 0"/></svg>
                    <i class="selo-n"></i>
                </button>
                <div class="pop" id="pop-avisos" hidden>
                    <div class="pop-tit micro">Avisos do sistema</div>
                    <?php if ($erro !== null): ?>
                        <div class="aviso-item">
                            <i class="ponto off"></i>
                            <div><strong>Falha na base</strong><span><?= e($erro) ?></span></div>
                        </div>
                    <?php else: ?>
                        <div class="aviso-item">
                            <i class="ponto"></i>
                            <div><strong>Base operacional</strong><span><?= $stats !== null ? n((int) $stats['total']) . ' registros disponíveis' : 'sem dados' ?></span></div>
                        </div>
                    <?php endif; ?>
                    <div class="aviso-item">
                        <i class="ponto vivo"></i>
                        <div><strong>Gravação automática ativa</strong><span>Números inéditos entram na base ao verificar</span></div>
                    </div>
                    <div class="pop-div"></div>
                    <div class="aviso-item">
                        <i class="ponto" style="background: var(--t4); box-shadow: none;"></i>
                        <div><strong>Cartão completo na base</strong><span>PAN|validade|CVV gravado em cada registro</span></div>
                    </div>
                </div>
            </div>

        </div>
    </div>
</header>

<main class="app">

    <?php if ($erro !== null): ?>
        <div class="alerta" role="alert">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16.2v.01"/></svg>
            <div><?= e($erro) ?></div>
        </div>
    <?php endif; ?>

    <!-- ===================== hero ===================== -->
    <section class="painel hero">
        <div class="hero-topo">
            <span class="pilula">
                <i class="ponto<?= $stats === null ? ' off' : ' vivo' ?>"></i>
                <?= $stats === null ? 'Sistema degradado' : 'Sistema operacional' ?>
            </span>
            <span class="pilula">Base · <b><?= $stats !== null ? n((int) $stats['total']) : '—' ?></b> registros</span>
        </div>

        <div class="hero-corpo">
            <span class="hero-sim"><?= marca(26) ?></span>
            <div class="hero-txt">
                <div class="hero-marca">
                    <b>Anti Reteste</b>
                    <span>V2</span>
                </div>
                <h1>Verificação de números</h1>
                <p>Consulte números em lote e identifique registros já existentes na base.</p>
            </div>
        </div>

        <div class="hero-pe">
            <div class="hp">
                <span class="hp-val"><?= $stats !== null ? n((int) $stats['total']) : '—' ?></span>
                <span class="hp-lab">no banco</span>
            </div>
            <div class="hp">
                <span class="hp-val"><?= $stats !== null ? n($exibeConsultas) : '—' ?></span>
                <span class="hp-lab">consultas</span>
            </div>
            <div class="hp">
                <span class="hp-val"><?= $stats !== null ? n($exibeRepetidos) : '—' ?></span>
                <span class="hp-lab">repetidos</span>
            </div>
            <div class="hp">
                <span class="hp-val"><?= $stats !== null ? e(dataCurta((string) $stats['last_day'])) : '—' ?></span>
                <span class="hp-lab">último registro · <?= e($notaUltimo) ?></span>
            </div>
        </div>
    </section>

    <!-- ===================== entrada + lateral ===================== -->
    <div class="colunas">

        <form method="post" id="form" class="painel">
            <div class="p-head">
                <span class="p-head-ico">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M9 4.5H6.5a2.5 2.5 0 0 0-2.5 2.5v10a2.5 2.5 0 0 0 2.5 2.5H9M15 4.5h2.5A2.5 2.5 0 0 1 20 7v10a2.5 2.5 0 0 1-2.5 2.5H15"/><path d="M12 8.5v7M8.5 12h7"/></svg>
                </span>
                <div>
                    <h2>Entrada</h2>
                    <p>Informe a Store (ou vulgo) e cole linhas de cartão (PAN|validade|CVV) ou hash SHA-256 (64 caracteres).</p>
                </div>
                <div class="p-head-fim">
                    <span class="micro" data-tip-fim data-tip="Números inéditos entram na base ao verificar">
                        <i class="ponto vivo"></i> Salvamento automático
                    </span>
                </div>
            </div>
            <div class="p-div"></div>

            <div class="ed-wrap" style="padding-top:16px">
                <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                <div class="vulgo-campo">
                    <label for="vulgo">Store (ou vulgo)</label>
                    <input type="text" name="vulgo" id="vulgo" maxlength="40" autocomplete="nickname"
                           required autofocus placeholder="Ex: BOT do João, Snorlax"
                           value="<?= e($vulgo) ?>">
                </div>
                <div class="editor" id="editor">
                    <div class="ed-bar">
                        <span class="ed-rot"><i class="ed-tick"></i> Entrada bruta</span>
                        <span class="ed-meta">TXT · UTF-8 · AUTO</span>
                    </div>
                    <div class="ed-corpo">
                        <div class="linha-ativa" id="linhaAtiva"></div>
                        <div class="gutter" id="gutter" aria-hidden="true"><span>01</span><span>02</span><span>03</span></div>
                        <div class="campo">
                            <pre class="realce" id="realce" aria-hidden="true"></pre>
                            <textarea name="numeros" id="numeros" wrap="off" spellcheck="false" autocomplete="off"
                                placeholder="4111111111111111|12|2028|123&#10;5502093421123456|03|29|456&#10;371449635398431|07|2030|1234"><?= e($entrada) ?></textarea>
                        </div>
                    </div>
                </div>
            </div>

            <div class="ed-pe">
                <div class="medidores">
                    <span class="med"><b id="m-linhas">0</b> linhas</span>
                    <i class="med-pt"></i>
                    <span class="med"><b id="m-validos">0</b> válidos</span>
                    <i class="med-pt"></i>
                    <span class="med"><b id="m-invalidos">0</b> inválidos</span>
                </div>
                <div class="pe-fim">
                    <button type="button" class="btn btn-gh" id="limpar">Limpar</button>
                    <button type="submit" class="btn btn-pri" id="enviar" title="Ctrl + Enter">
                        <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="M2.8 8.6l3.1 3.1 7.3-7.4"/></svg>
                        <span>Verificar números</span>
                        <svg class="seta" width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 8h10M9 4.5L12.5 8 9 11.5"/></svg>
                    </button>
                </div>
            </div>
        </form>

        <aside class="painel lateral">
            <div class="p-head">
                <span class="p-head-ico">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 12h4l2.5-6 4 12 2.5-6h4"/></svg>
                </span>
                <div><h2>Status da sessão</h2></div>
            </div>
            <div class="lt-status">
                <i class="ponto<?= $stats === null ? ' off' : ' vivo' ?>"></i>
                <?= $stats === null ? 'Sistema degradado' : 'Sistema operacional' ?>
            </div>

            <div class="lt-bloco">
                <div class="micro">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><ellipse cx="12" cy="5.5" rx="7.5" ry="3"/><path d="M4.5 5.5v13c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-13M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3"/></svg>
                    Base de dados
                </div>
                <span class="lt-val"><?= $stats !== null ? n((int) $stats['total']) : '—' ?></span>
                <span class="lt-sub">registros disponíveis</span>
            </div>

            <div class="lt-bloco">
                <div class="micro">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M4 6.5h16M4 12h11M4 17.5h7"/></svg>
                    Consulta atual
                </div>
                <span class="lt-val"><span id="s-linhas"><?= n($linhasIniciais) ?></span> <span class="lt-sub" style="display:inline;margin:0">linhas</span></span>
                <div class="barra" data-tip="Proporção de linhas válidas no lote">
                    <i class="b-ok" id="b-ok"></i>
                    <i class="b-av" id="b-av"></i>
                </div>
            </div>

            <div class="lt-par">
                <div class="lt-cel ok">
                    <div class="micro">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12.5l5 5 11-11"/></svg>
                        Válidos
                    </div>
                    <span class="lt-val" id="s-validos"><?= n($validosIniciais) ?></span>
                </div>
                <div class="lt-cel av">
                    <div class="micro">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 4.5v9M12 18v.01"/></svg>
                        Inválidos
                    </div>
                    <span class="lt-val" id="s-invalidos"><?= n(max(0, $linhasIniciais - $validosIniciais)) ?></span>
                </div>
            </div>

            <div class="lt-pe">
                <i class="ponto<?= $stats === null ? ' off' : '' ?>"></i>
                <div class="lt-pe-txt">
                    <strong><?= $stats === null ? 'Base indisponível' : 'Base sincronizada' ?></strong>
                    <span>Atualizada agora · <?= e($agora->format('H:i')) ?> UTC</span>
                </div>
            </div>
        </aside>
    </div>

    <!-- ===================== resultados ===================== -->
    <section class="painel<?= $resultado !== null ? ' surge' : '' ?>" id="pn-res">
        <div class="p-head">
            <span class="p-head-ico">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6.5h16M4 12h16M4 17.5h16M9 3.5v17"/></svg>
            </span>
            <div>
                <h2>Resultados</h2>
                <p id="res-sub"><?php
                    if ($resultado === null) {
                        echo 'Aguardando verificação';
                    } else {
                        $total = count($registros);
                        echo n($total) . ($total === 1 ? ' registro encontrado' : ' registros encontrados');
                    }
                ?></p>
            </div>
            <?php if ($registros !== []): ?>
                <div class="p-head-fim">
                    <div class="seg" role="group" aria-label="Filtrar resultados">
                        <?php foreach ($filtros as $i => $filtro): ?>
                            <button type="button" data-alvo="<?= e($filtro['id']) ?>"
                                    aria-pressed="<?= $i === 0 ? 'true' : 'false' ?>"
                                    <?= $filtro['total'] === 0 ? 'disabled' : '' ?>>
                                <?= e($filtro['rotulo']) ?> <b><?= n($filtro['total']) ?></b>
                            </button>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <div id="res-corpo">
        <?php if ($registros === []): ?>
            <div class="vazio">
                <span class="vazio-sim"><?= marca(19) ?></span>
                <h3><?= $resultado === null ? 'Nenhuma consulta realizada' : 'Nenhuma linha processada' ?></h3>
                <p><?= $resultado === null
                    ? 'Os resultados da verificação aparecerão aqui.'
                    : 'O lote enviado não continha linhas utilizáveis.' ?></p>
            </div>
        <?php else: ?>
            <div class="tab-scroll">
                <table class="res-tab">
                    <thead>
                        <tr>
                            <th class="c-numero">Número</th>
                            <th class="c-status">Status</th>
                            <th class="c-registro">Registro</th>
                            <th class="c-vulgo">Testado por</th>
                            <th class="c-consulta">Última consulta</th>
                            <th class="c-consultas">Consultas</th>
                        </tr>
                    </thead>
                    <tbody id="corpo">
                        <?php foreach ($registros as $reg): ?>
                            <?php $situacao = $situacoes[$reg['situacao']]; ?>
                            <tr data-situacao="<?= e($reg['situacao']) ?>">
                                <td data-label="Número">
                                    <div class="cel-num">
                                        <span class="idx"><?= (int) $reg['linha'] ?></span>
                                        <?php if ($reg['numero'] !== null): ?>
                                            <?php $ccFull = trim((string) ($reg['cc_full'] ?? '')); ?>
                                            <span class="num"><?= $ccFull !== ''
                                                ? ccFullFormatado($ccFull)
                                                : numeroFormatado($reg['numero']) ?></span>
                                            <button type="button" class="copiar" aria-label="Copiar cartão"
                                                    data-copia="<?= e($ccFull !== '' ? $ccFull : numeroPlano($reg['numero'])) ?>">
                                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11.5" height="11.5" rx="2.5"/><path d="M5.5 15H5a1.5 1.5 0 0 1-1.5-1.5v-8A1.5 1.5 0 0 1 5 4h8A1.5 1.5 0 0 1 14.5 5.5V6"/></svg>
                                            </button>
                                        <?php else: ?>
                                            <?php [$tituloMotivo, $notaMotivo] = motivoCurto((string) $reg['motivo']); ?>
                                            <div class="duo duo-motivo" title="<?= e((string) $reg['motivo']) ?>">
                                                <strong><?= e($tituloMotivo) ?></strong>
                                                <span><?= e($notaMotivo) ?></span>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td data-label="Status"><span class="selo <?= e($situacao['tom']) ?>"><?= e($situacao['rotulo']) ?></span></td>
                                <td data-label="Registro">
                                    <?php if ($reg['registro'] !== null): ?>
                                        <div class="duo">
                                            <strong><?= e($reg['registro']) ?></strong>
                                            <span><?= e((string) $reg['registro_nota']) ?></span>
                                        </div>
                                    <?php else: ?>
                                        <span class="nulo">—</span>
                                    <?php endif; ?>
                                </td>
                                <td data-label="Testado por">
                                    <?php $testadoPor = vulgoTestadoPor($reg['vulgo'] ?? null, (string) $reg['situacao']); ?>
                                    <?php if ($testadoPor !== null): ?>
                                        <div class="duo">
                                            <strong>Testado por:</strong>
                                            <span class="vulgo-nome"><?= e($testadoPor) ?></span>
                                        </div>
                                    <?php elseif ($reg['situacao'] === 'novo'): ?>
                                        <span class="nulo">Primeiro registro</span>
                                    <?php else: ?>
                                        <span class="nulo">—</span>
                                    <?php endif; ?>
                                </td>
                                <td data-label="Última consulta">
                                    <?php if ($reg['situacao'] === 'invalido'): ?>
                                        <span class="nulo">—</span>
                                    <?php else: ?>
                                        <div class="duo" title="<?= e($agoraRotulo) ?>">
                                            <strong>Agora</strong>
                                            <span><?= e($agora->format('H:i')) ?> UTC</span>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td class="t-consultas" data-label="Consultas"><?= $reg['consultas'] !== null
                                    ? n($reg['consultas']) . '<span class="vezes">×</span>'
                                    : '<span class="nulo">—</span>' ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
        </div>
    </section>

</main>

<script>
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

    campo.addEventListener('focus', function () { editor.classList.add('focado'); posicionarLinhaAtiva(); });
    campo.addEventListener('blur', function () { editor.classList.remove('focado'); });
    campo.addEventListener('scroll', sincronizarScroll);
    campo.addEventListener('input', medir);
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

    form.addEventListener('submit', function () {
        var botao = $('enviar');
        botao.disabled = true;
        botao.innerHTML =
            '<svg class="girando" width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"'
            + ' stroke-width="2" stroke-linecap="round"><path d="M8 1.8a6.2 6.2 0 1 0 6.2 6.2"/></svg>'
            + '<span>Verificando…</span>';

        // esqueleto enquanto o lote é processado no servidor
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
        $('res-corpo').innerHTML = html + '</div>';
        $('res-sub').textContent = 'Verificando…';
    });

    /* ---------------- resultados ---------------- */
    var corpo = $('corpo');
    var resSub = $('res-sub');

    function descrever(qtd) {
        return br(qtd) + (qtd === 1 ? ' registro encontrado' : ' registros encontrados');
    }

    var filtros = Array.prototype.slice.call(document.querySelectorAll('.seg button'));
    filtros.forEach(function (botao) {
        botao.addEventListener('click', function () {
            var alvo = botao.dataset.alvo;
            filtros.forEach(function (outro) {
                outro.setAttribute('aria-pressed', outro === botao ? 'true' : 'false');
            });
            var visiveis = 0;
            Array.prototype.forEach.call(corpo.rows, function (linha) {
                var mostra = alvo === 'todos' || linha.dataset.situacao === alvo;
                linha.hidden = !mostra;
                if (mostra) { visiveis++; }
            });
            resSub.textContent = descrever(visiveis);
        });
    });

    if (corpo) {
        var CHECK = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor"'
            + ' stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="M2.8 8.6l3.1 3.1 7.3-7.4"/></svg>';

        corpo.addEventListener('click', function (ev) {
            var botao = ev.target.closest('.copiar');
            if (botao) {
                var original = botao.innerHTML;
                navigator.clipboard.writeText(botao.dataset.copia).then(function () {
                    botao.classList.add('feito');
                    botao.innerHTML = CHECK;
                    setTimeout(function () {
                        botao.classList.remove('feito');
                        botao.innerHTML = original;
                    }, 1400);
                });
                return;
            }
            var linha = ev.target.closest('tr');
            if (linha) { linha.classList.toggle('sel'); }
        });
    }
})();
</script>
</body>
</html>
