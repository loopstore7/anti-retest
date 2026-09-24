<?php

declare(strict_types=1);

/**
 * Lê e escreve no mesmo banco SQLite do pacote Python (mesma tabela, mesma
 * chave HMAC), então CLI, GUI e web compartilham o histórico.
 */

require_once __DIR__ . DIRECTORY_SEPARATOR . 'DailyLog.php';

final class InvalidNumberException extends RuntimeException
{
}

final class AntiRetest
{
    public const PAN_LENGTH = 16;
    public const AMEX_LENGTH = 15;
    public const AMEX_PREFIXES = ['34', '37'];
    public const PAN_LENGTHS = [self::PAN_LENGTH, self::AMEX_LENGTH];
    public const CVV_LENGTH = 3;
    public const AMEX_CVV_LENGTH = 4;
    private const YEAR_MIN = 2000;
    private const YEAR_MAX = 2099;
    /** Linha estranha com muitos números: além disso não vale procurar combinação. */
    private const MAX_TOKENS = 12;

    private const SCHEMA = <<<'SQL'
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    fingerprint   TEXT PRIMARY KEY,
    bin           TEXT NOT NULL,
    last4         TEXT NOT NULL,
    added_at      TEXT NOT NULL,
    added_on      TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 1,
    pan_length    INTEGER NOT NULL DEFAULT 16,
    vulgo         TEXT NOT NULL DEFAULT '',
    cc_full       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS entries_added_on_idx ON entries (added_on);
SQL;

    private PDO $pdo;
    private string $key;
    private ?DailyLog $log;

    /**
     * Sem $logDir nada em claro sai daqui; com $logDir, cada linha verificada
     * também vai para o txt do dia naquela pasta, com a marca do resultado.
     */
    public function __construct(string $dbPath, ?string $logDir = null)
    {
        $this->pdo = new PDO('sqlite:' . $dbPath, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->pdo->exec(self::SCHEMA);
        $this->migrate();
        $this->key = $this->resolveKey();
        $this->log = $logDir !== null ? new DailyLog($logDir) : null;
    }

    /** Bancos antigos: Amex (pan_length) e depois o vulgo de quem registrou. */
    private function migrate(): void
    {
        $colunas = [];
        foreach ($this->pdo->query('PRAGMA table_info(entries)')->fetchAll() as $coluna) {
            $colunas[] = (string) $coluna['name'];
        }
        if (!in_array('pan_length', $colunas, true)) {
            $this->pdo->exec('ALTER TABLE entries ADD COLUMN pan_length INTEGER NOT NULL DEFAULT 16');
        }
        if (!in_array('vulgo', $colunas, true)) {
            $this->pdo->exec("ALTER TABLE entries ADD COLUMN vulgo TEXT NOT NULL DEFAULT ''");
        }
        if (!in_array('cc_full', $colunas, true)) {
            $this->pdo->exec("ALTER TABLE entries ADD COLUMN cc_full TEXT NOT NULL DEFAULT ''");
        }
    }

    /** Linha completa do cartão: PAN|MM|AAAA|CVV. */
    public static function formatCcFull(string $pan, int $month, int $year, string $cvv): string
    {
        return $pan . '|' . sprintf('%02d', $month) . '|' . $year . '|' . $cvv;
    }

    /** @param array{pan:string, month:int, year:int, cvv:string} $entrada */
    public static function formatCcFullFromEntry(array $entrada): string
    {
        return self::formatCcFull(
            $entrada['pan'],
            $entrada['month'],
            $entrada['year'],
            $entrada['cvv'],
        );
    }

    /** Nome/vulgo do cliente: limpa controle e corta em 40 caracteres. */
    public static function sanitizeVulgo(string $raw): string
    {
        $limpo = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', '', $raw));
        if ($limpo === '') {
            return '';
        }
        if (function_exists('mb_substr')) {
            return mb_substr($limpo, 0, 40, 'UTF-8');
        }

        return substr($limpo, 0, 40);
    }

    /** Mascara vulgo/nome da store: só as 3 primeiras letras visíveis (ex.: Sexta → Sex**). */
    public static function maskVulgo(string $raw): string
    {
        $v = self::sanitizeVulgo($raw);
        if ($v === '') {
            return '';
        }
        $len = function_exists('mb_strlen') ? mb_strlen($v, 'UTF-8') : strlen($v);
        if ($len <= 2) {
            $head = function_exists('mb_substr') ? mb_substr($v, 0, 1, 'UTF-8') : substr($v, 0, 1);

            return $head . '*';
        }
        if ($len <= 3) {
            return $v;
        }
        $head = function_exists('mb_substr') ? mb_substr($v, 0, 3, 'UTF-8') : substr($v, 0, 3);

        return $head . str_repeat('*', $len - 3);
    }

    /** Linha com fingerprint SHA-256 (64 hex) para consulta direta. */
    public static function isFingerprintLine(string $line): bool
    {
        return (bool) preg_match('/^[a-f0-9]{64}$/i', trim($line));
    }

    private function resolveKey(): string
    {
        $fromEnv = getenv('ANTIRETEST_KEY');
        if (is_string($fromEnv) && $fromEnv !== '') {
            return $fromEnv;
        }
        $stored = $this->pdo->query("SELECT value FROM meta WHERE key = 'key'")->fetchColumn();
        if (is_string($stored) && $stored !== '') {
            return (string) hex2bin($stored);
        }
        $generated = random_bytes(32);
        $insert = $this->pdo->prepare("INSERT INTO meta (key, value) VALUES ('key', ?)");
        $insert->execute([bin2hex($generated)]);

        return $generated;
    }

    public static function isAmex(string $pan): bool
    {
        return strlen($pan) === self::AMEX_LENGTH
            && in_array(substr($pan, 0, 2), self::AMEX_PREFIXES, true);
    }

    /** Amex usa CVV de 4 dígitos; as outras bandeiras, 3. */
    public static function cvvLength(string $pan): int
    {
        return self::isAmex($pan) ? self::AMEX_CVV_LENGTH : self::CVV_LENGTH;
    }

    /** 16 dígitos, ou 15 começando em 34/37 (Amex), sempre com Luhn válido. */
    public static function looksLikePan(string $digits): bool
    {
        if (!ctype_digit($digits)) {
            return false;
        }
        if (strlen($digits) === self::AMEX_LENGTH) {
            return self::isAmex($digits) && self::luhnOk($digits);
        }

        return strlen($digits) === self::PAN_LENGTH && self::luhnOk($digits);
    }

    /**
     * Lê a linha completa: PAN, validade e CVV, nenhum deles opcional.
     *
     * Aceita o que vem em volta ("Reprovada PAN|MM|AA|CVV - Refused") e os
     * separadores | ; , : / \ e tabulação. Dentro de um campo, espaço, ponto,
     * hífen e sublinhado são só formatação.
     *
     * @return array{pan:string, month:int, year:int, cvv:string}
     */
    public static function parseEntry(string $line): array
    {
        $tokens = self::numericTokens($line);
        $entrada = self::fromFields($tokens) ?? self::fromSingleRun($tokens);
        if ($entrada === null) {
            throw new InvalidNumberException(self::explain($tokens));
        }

        return $entrada;
    }

    /**
     * Extrai só o PAN de uma linha e valida o Luhn.
     *
     * Caminho de forget e da exibição, onde exigir validade e CVV não faria
     * sentido: para gravar no banco, quem manda é parseEntry.
     */
    public static function normalize(string $number): string
    {
        $tokens = self::numericTokens($number);
        foreach ($tokens as $token) {
            if (self::looksLikePan($token)) {
                return $token;
            }
        }
        if (count($tokens) === 1) {
            foreach (self::PAN_LENGTHS as $tamanho) {
                $inicio = substr($tokens[0], 0, $tamanho);
                if (self::looksLikePan($inicio)) {
                    return $inicio;
                }
            }
        }

        throw new InvalidNumberException(self::explainPan($tokens));
    }

    /**
     * Todos os PANs de uma linha, na ordem em que aparecem; usada para exibir
     * o número completo do lote atual.
     *
     * @return list<string>
     */
    public static function extractPans(string $line): array
    {
        $pans = [];
        foreach (self::numericTokens($line) as $token) {
            if (self::looksLikePan($token)) {
                $pans[] = $token;
            }
        }
        if ($pans !== []) {
            return $pans;
        }
        try {
            return [self::normalize($line)];
        } catch (InvalidNumberException) {
            return [];
        }
    }

    /**
     * Sequências de dígitos da linha, campo por campo, na ordem.
     *
     * @return list<string>
     */
    private static function numericTokens(string $raw): array
    {
        $tokens = [];
        foreach (preg_split('/[|;,:\/\\\\\t]+/', $raw) ?: [] as $field) {
            $compact = preg_replace('/[\s._-]+/', '', $field) ?? '';
            preg_match_all('/\d+/', $compact, $encontrados);
            foreach ($encontrados[0] as $token) {
                $tokens[] = $token;
            }
        }

        return $tokens;
    }

    /**
     * Caso normal: cada dado num campo (PAN|MM|AAAA|CVV, em qualquer ordem).
     *
     * @param list<string> $tokens
     * @return array{pan:string, month:int, year:int, cvv:string}|null
     */
    private static function fromFields(array $tokens): ?array
    {
        $limite = array_slice($tokens, 0, self::MAX_TOKENS);
        foreach ($limite as $index => $token) {
            if (!self::looksLikePan($token)) {
                continue;
            }
            $resto = array_values(array_merge(
                array_slice($limite, 0, $index),
                array_slice($limite, $index + 1)
            ));
            $validade = self::pickExpiryAndCvv($resto, self::cvvLength($token));
            if ($validade !== null) {
                return ['pan' => $token] + $validade;
            }
        }

        return null;
    }

    /**
     * Mês, ano e CVV na ordem em que aparecem, ignorando números extras.
     *
     * @param list<string> $tokens
     * @return array{month:int, year:int, cvv:string}|null
     */
    private static function pickExpiryAndCvv(array $tokens, int $cvvLen): ?array
    {
        foreach ($tokens as $index => $token) {
            $juntos = self::expiryFromToken($token);
            if ($juntos !== null) {
                $cvv = self::firstCvv(array_slice($tokens, $index + 1), $cvvLen);
                if ($cvv !== null) {
                    return ['month' => $juntos[0], 'year' => $juntos[1], 'cvv' => $cvv];
                }
            }

            $month = self::month($token);
            if ($month === null) {
                continue;
            }
            for ($seguinte = $index + 1; $seguinte < count($tokens); $seguinte++) {
                $year = self::year($tokens[$seguinte]);
                if ($year === null) {
                    continue;
                }
                $cvv = self::firstCvv(array_slice($tokens, $seguinte + 1), $cvvLen);
                if ($cvv !== null) {
                    return ['month' => $month, 'year' => $year, 'cvv' => $cvv];
                }
            }
        }

        return null;
    }

    /**
     * Tudo emendado, sem separador ("4111111111111111 12 2028 123").
     *
     * @param list<string> $tokens
     * @return array{pan:string, month:int, year:int, cvv:string}|null
     */
    private static function fromSingleRun(array $tokens): ?array
    {
        if (count($tokens) !== 1) {
            return null;
        }
        $digits = $tokens[0];
        foreach (self::PAN_LENGTHS as $tamanho) {
            $pan = substr($digits, 0, $tamanho);
            if (!self::looksLikePan($pan)) {
                continue;
            }
            $resto = substr($digits, $tamanho);
            foreach ([4, 2] as $yearLen) {
                if (strlen($resto) !== 2 + $yearLen + self::cvvLength($pan)) {
                    continue;
                }
                $month = self::month(substr($resto, 0, 2));
                $year = self::year(substr($resto, 2, $yearLen));
                if ($month !== null && $year !== null) {
                    return [
                        'pan' => $pan,
                        'month' => $month,
                        'year' => $year,
                        'cvv' => substr($resto, 2 + $yearLen),
                    ];
                }
            }
        }

        return null;
    }

    /** Validade num campo só ("1228" ou "122028").
     *
     * @return array{0:int,1:int}|null
     */
    private static function expiryFromToken(string $token): ?array
    {
        if (!in_array(strlen($token), [4, 6], true)) {
            return null;
        }
        $month = self::month(substr($token, 0, 2));
        $year = self::year(substr($token, 2));
        if ($month === null || $year === null) {
            return null;
        }

        return [$month, $year];
    }

    private static function month(string $token): ?int
    {
        if (!ctype_digit($token) || strlen($token) > 2 || $token === '') {
            return null;
        }
        $valor = (int) $token;

        return $valor >= 1 && $valor <= 12 ? $valor : null;
    }

    /** Ano de 2 ou 4 dígitos; 29 vira 2029. */
    private static function year(string $token): ?int
    {
        if (!ctype_digit($token)) {
            return null;
        }
        if (strlen($token) === 2) {
            return 2000 + (int) $token;
        }
        if (strlen($token) === 4 && (int) $token >= self::YEAR_MIN && (int) $token <= self::YEAR_MAX) {
            return (int) $token;
        }

        return null;
    }

    /** @param list<string> $tokens */
    private static function firstCvv(array $tokens, int $cvvLen): ?string
    {
        foreach ($tokens as $token) {
            if (strlen($token) === $cvvLen) {
                return $token;
            }
        }

        return null;
    }

    /** @param list<string> $tokens */
    private static function explain(array $tokens): string
    {
        foreach ($tokens as $token) {
            if (self::looksLikePan($token)) {
                return sprintf(
                    'falta a validade ou o CVV: envie PAN|MM|AAAA|CVV'
                    . ' (mês 01-12, ano, CVV de %d dígitos%s)',
                    self::cvvLength($token),
                    self::isAmex($token) ? ' — Amex' : ''
                );
            }
        }

        return self::explainPan($tokens);
    }

    /** @param list<string> $tokens */
    private static function explainPan(array $tokens): string
    {
        if ($tokens === []) {
            return 'nenhum número na linha';
        }

        return 'nenhum cartão válido: são 16 dígitos (ou 15 começando em 34/37, Amex)'
            . ' com dígito verificador (Luhn) correto';
    }

    public static function luhnOk(string $digits): bool
    {
        $total = 0;
        $reversed = strrev($digits);
        for ($i = 0, $n = strlen($reversed); $i < $n; $i++) {
            $value = (int) $reversed[$i];
            if ($i % 2 === 1) {
                $value *= 2;
                if ($value > 9) {
                    $value -= 9;
                }
            }
            $total += $value;
        }

        return $total % 10 === 0;
    }

    /** BIN + últimos 4: único formato exibido, o número inteiro nunca é gravado. */
    public static function mask(string $digits): string
    {
        return substr($digits, 0, 6) . str_repeat('*', strlen($digits) - 10) . substr($digits, -4);
    }

    public function fingerprint(string $digits): string
    {
        return hash_hmac('sha256', $digits, $this->key);
    }

    private static function nowUtc(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }

    private static function daysBetween(DateTimeImmutable $from, DateTimeImmutable $to): int
    {
        $a = new DateTimeImmutable($from->format('Y-m-d'), new DateTimeZone('UTC'));
        $b = new DateTimeImmutable($to->format('Y-m-d'), new DateTimeZone('UTC'));

        return (int) $a->diff($b)->format('%r%a');
    }

    /** Validade já passou? Comparação no mesmo fuso do txt diário. */
    private static function isExpired(int $month, int $year): bool
    {
        $hoje = new DateTimeImmutable('now', DailyLog::zone());

        return [$year, $month] < [(int) $hoje->format('Y'), (int) $hoje->format('n')];
    }

    /**
     * Consulta por fingerprint (hash SHA-256). Só funciona se o hash já existir na base.
     *
     * @return array<string,mixed>
     */
    public function checkByFingerprint(
        string $fingerprint,
        bool $record = true,
        ?string $rawLine = null,
    ): array {
        $fingerprint = strtolower(trim($fingerprint));
        $now = self::nowUtc();

        $select = $this->pdo->prepare('SELECT * FROM entries WHERE fingerprint = ?');
        $select->execute([$fingerprint]);
        $row = $select->fetch();
        if ($row === false) {
            throw new InvalidNumberException('Hash não encontrado na base.');
        }

        $panLength = (int) ($row['pan_length'] ?? 16);
        $masked = $row['bin'] . str_repeat('*', max(0, $panLength - 10)) . $row['last4'];
        $addedAt = new DateTimeImmutable((string) $row['added_at']);
        $daysSince = self::daysBetween($addedAt, $now);
        $attempts = (int) $row['attempts'] + ($record ? 1 : 0);
        $vulgoGravado = self::sanitizeVulgo((string) ($row['vulgo'] ?? ''));
        $ccFull = trim((string) ($row['cc_full'] ?? ''));

        if ($record) {
            $update = $this->pdo->prepare(
                'UPDATE entries SET attempts = ?, last_seen_at = ? WHERE fingerprint = ?'
            );
            $update->execute([$attempts, $now->format('Y-m-d\TH:i:s.uP'), $fingerprint]);
            if ($this->log !== null) {
                $this->log->appendMarks($rawLine ?? $fingerprint, [DailyLog::MARK_KNOWN], $now);
            }
        }

        return [
            'masked' => $masked,
            'fingerprint' => $fingerprint,
            'is_retest' => true,
            'status' => 'known',
            'recorded' => false,
            'added_on' => $addedAt->format('Y-m-d'),
            'days_since_added' => $daysSince,
            'attempts' => $attempts,
            'expiry' => '—',
            'expired' => false,
            'vulgo' => $vulgoGravado,
            'cc_full' => $ccFull,
            'lookup_by_hash' => true,
        ];
    }

    /**
     * Consulta uma linha completa (PAN|MM|AAAA|CVV). Com $record = true, grava
     * a inclusão (se novo) ou incrementa a tentativa (se já existia).
     *
     * $rawLine é o que vai para o txt do dia: em lote, $number chega já
     * reduzido à linha do cartão, e o txt guarda o que foi digitado.
     * $vulgo é o nome de quem está registrando; só grava em inclusão nova.
     *
     * @return array<string,mixed>
     */
    public function check(
        string $number,
        bool $record = true,
        ?string $rawLine = null,
        string $vulgo = ''
    ): array {
        $now = self::nowUtc();
        $vulgo = self::sanitizeVulgo($vulgo);
        try {
            $entrada = self::parseEntry($number);
        } catch (InvalidNumberException $erro) {
            // A linha não serve para o banco, mas fica registrada no txt do dia.
            if ($record && $this->log !== null) {
                $this->log->append($rawLine ?? $number, DailyLog::MARK_INVALID, $now);
            }
            throw $erro;
        }
        $digits = $entrada['pan'];
        $ccFull = self::formatCcFullFromEntry($entrada);
        $expiry = sprintf('%02d/%d', $entrada['month'], $entrada['year']);
        $expired = self::isExpired($entrada['month'], $entrada['year']);
        $marcas = $expired ? [DailyLog::MARK_EXPIRED] : [];
        $fingerprint = $this->fingerprint($digits);

        $select = $this->pdo->prepare('SELECT * FROM entries WHERE fingerprint = ?');
        $select->execute([$fingerprint]);
        $row = $select->fetch();

        if ($row === false) {
            if ($record) {
                $insert = $this->pdo->prepare(
                    'INSERT INTO entries'
                    . ' (fingerprint, bin, last4, added_at, added_on, last_seen_at,'
                    . ' attempts, pan_length, vulgo, cc_full)'
                    . ' VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)'
                );
                $insert->execute([
                    $fingerprint,
                    substr($digits, 0, 6),
                    substr($digits, -4),
                    $now->format('Y-m-d\TH:i:s.uP'),
                    $now->format('Y-m-d'),
                    $now->format('Y-m-d\TH:i:s.uP'),
                    strlen($digits),
                    $vulgo,
                    $ccFull,
                ]);
                if ($this->log !== null) {
                    $this->log->appendMarks($rawLine ?? $number, [DailyLog::MARK_NEW, ...$marcas], $now);
                }
            }

            return [
                'masked' => self::mask($digits),
                'fingerprint' => $fingerprint,
                'is_retest' => false,
                'status' => 'new',
                'recorded' => $record,
                'added_on' => $now->format('Y-m-d'),
                'days_since_added' => 0,
                'attempts' => 1,
                'expiry' => $expiry,
                'expired' => $expired,
                'vulgo' => $vulgo,
                'cc_full' => $ccFull,
            ];
        }

        $addedAt = new DateTimeImmutable((string) $row['added_at']);
        $daysSince = self::daysBetween($addedAt, $now);
        $attempts = (int) $row['attempts'] + ($record ? 1 : 0);
        $vulgoGravado = self::sanitizeVulgo((string) ($row['vulgo'] ?? ''));

        if ($record) {
            $update = $this->pdo->prepare(
                'UPDATE entries SET attempts = ?, last_seen_at = ?, cc_full = ? WHERE fingerprint = ?'
            );
            $update->execute([
                $attempts,
                $now->format('Y-m-d\TH:i:s.uP'),
                $ccFull,
                $fingerprint,
            ]);
            if ($this->log !== null) {
                $this->log->appendMarks($rawLine ?? $number, [DailyLog::MARK_KNOWN, ...$marcas], $now);
            }
        } else {
            $ccFull = trim((string) ($row['cc_full'] ?? '')) ?: $ccFull;
        }

        return [
            'masked' => self::mask($digits),
            'fingerprint' => $fingerprint,
            'is_retest' => true,
            'status' => 'known',
            'recorded' => false,
            'added_on' => $addedAt->format('Y-m-d'),
            'days_since_added' => $daysSince,
            'attempts' => $attempts,
            'expiry' => $expiry,
            'expired' => $expired,
            'vulgo' => $vulgoGravado,
            'cc_full' => $ccFull,
        ];
    }

    /**
     * Processa uma lista de números, separando novos, já conhecidos, repetidos
     * dentro do próprio lote e inválidos.
     *
     * @param string[] $numbers
     * @return array{new:list<array<string,mixed>>, known:list<array<string,mixed>>, duplicated:list<array<string,mixed>>, invalid:list<array<string,mixed>>, total:int}
     */
    public function checkMany(array $numbers, bool $recordNew = false, string $vulgo = ''): array
    {
        $result = ['new' => [], 'known' => [], 'duplicated' => [], 'invalid' => [], 'total' => 0];
        $seen = [];
        $vulgo = self::sanitizeVulgo($vulgo);

        foreach ($numbers as $index => $number) {
            $number = trim((string) $number);
            if ($number === '') {
                continue;
            }
            $line = ((int) $index) + 1;
            $result['total']++;

            if (self::isFingerprintLine($number)) {
                $fp = strtolower(trim($number));
                if (isset($seen[$fp])) {
                    if ($recordNew) {
                        $this->bumpAttempts($fp, $number);
                    }
                    $result['duplicated'][] = [
                        'line' => $line,
                        'masked' => (string) ($seen[$fp]['masked'] ?? 'hash'),
                        'first_line' => $seen[$fp]['line'],
                        'vulgo' => $seen[$fp]['vulgo'],
                        'cc_full' => (string) ($seen[$fp]['cc_full'] ?? ''),
                    ];
                    continue;
                }
                try {
                    $entry = $this->checkByFingerprint($number, $recordNew, $number) + ['line' => $line];
                } catch (InvalidNumberException $error) {
                    $result['invalid'][] = [
                        'line' => $line,
                        'reason' => $error->getMessage(),
                        'vulgo' => null,
                    ];
                    if ($recordNew && $this->log !== null) {
                        $this->log->append($number, DailyLog::MARK_INVALID);
                    }
                    continue;
                }
                $seen[$fp] = [
                    'line' => $line,
                    'masked' => (string) ($entry['masked'] ?? ''),
                    'vulgo' => (string) ($entry['vulgo'] ?? ''),
                    'cc_full' => (string) ($entry['cc_full'] ?? ''),
                    'is_retest' => true,
                ];
                $result['known'][] = $entry;
                continue;
            }

            // A linha tem que vir completa: PAN, validade e CVV.
            try {
                $entrada = self::parseEntry($number);
            } catch (InvalidNumberException $error) {
                $result['invalid'][] = [
                    'line' => $line,
                    'reason' => $error->getMessage(),
                    'vulgo' => null,
                ];
                if ($recordNew && $this->log !== null) {
                    $this->log->append($number, DailyLog::MARK_INVALID);
                }
                continue;
            }

            $fingerprint = $this->fingerprint($entrada['pan']);
            $ccFull = self::formatCcFullFromEntry($entrada);
            if (isset($seen[$fingerprint])) {
                if ($recordNew && !empty($seen[$fingerprint]['is_retest'])) {
                    $this->bumpAttempts($fingerprint, $number, null, $ccFull);
                } elseif ($recordNew && $this->log !== null) {
                    $marcas = [DailyLog::MARK_KNOWN];
                    if (self::isExpired($entrada['month'], $entrada['year'])) {
                        $marcas[] = DailyLog::MARK_EXPIRED;
                    }
                    $this->log->appendMarks($number, $marcas);
                }
                $result['duplicated'][] = [
                    'line' => $line,
                    'masked' => self::mask($entrada['pan']),
                    'first_line' => $seen[$fingerprint]['line'],
                    'vulgo' => $seen[$fingerprint]['vulgo'],
                    'cc_full' => (string) ($seen[$fingerprint]['cc_full'] ?? $ccFull),
                ];
                continue;
            }

            $entry = $this->check($number, $recordNew, $number, $vulgo) + ['line' => $line];
            $seen[$fingerprint] = [
                'line' => $line,
                'vulgo' => (string) ($entry['vulgo'] ?? ''),
                'cc_full' => (string) ($entry['cc_full'] ?? $ccFull),
                'is_retest' => (bool) ($entry['is_retest'] ?? false),
            ];
            if ($entry['is_retest']) {
                $result['known'][] = $entry;
            } else {
                $result['new'][] = $entry;
            }
        }

        return $result;
    }

    public function forget(string $number): bool
    {
        $delete = $this->pdo->prepare('DELETE FROM entries WHERE fingerprint = ?');
        $delete->execute([$this->fingerprint(self::normalize($number))]);

        return $delete->rowCount() > 0;
    }

    /** Incrementa tentativas de um fingerprint já existente (reteste). */
    private function bumpAttempts(
        string $fingerprint,
        ?string $rawLine = null,
        ?DateTimeImmutable $now = null,
        string $ccFull = '',
    ): void {
        $moment = $now ?? self::nowUtc();
        if ($ccFull !== '') {
            $update = $this->pdo->prepare(
                'UPDATE entries SET attempts = attempts + 1, last_seen_at = ?, cc_full = ?'
                . ' WHERE fingerprint = ?'
            );
            $update->execute([$moment->format('Y-m-d\TH:i:s.uP'), $ccFull, $fingerprint]);
        } else {
            $update = $this->pdo->prepare(
                'UPDATE entries SET attempts = attempts + 1, last_seen_at = ? WHERE fingerprint = ?'
            );
            $update->execute([$moment->format('Y-m-d\TH:i:s.uP'), $fingerprint]);
        }
        if ($this->log !== null && $rawLine !== null && $rawLine !== '') {
            $this->log->append($rawLine, DailyLog::MARK_KNOWN, $moment);
        }
    }

    /** @return array<string,mixed> */
    public function stats(): array
    {
        $row = $this->pdo->query(
            'SELECT COUNT(*) AS total, COALESCE(SUM(attempts), 0) AS attempts,'
            . ' MIN(added_on) AS first_day, MAX(added_on) AS last_day FROM entries'
        )->fetch();
        $total = (int) $row['total'];
        $attempts = (int) $row['attempts'];
        $retested = (int) $this->pdo->query(
            'SELECT COUNT(*) AS n FROM entries WHERE attempts > 1'
        )->fetchColumn();

        return [
            'total' => $total,
            'attempts' => $attempts,
            /** Cada consulta além da 1ª gravação (reteste de registro existente). */
            'repetidos' => max(0, $attempts - $total),
            'retested' => $retested,
            'first_day' => $row['first_day'],
            'last_day' => $row['last_day'],
        ];
    }

    /**
     * Importa cartões de um arquivo texto (uma linha por entrada).
     *
     * Exige o mesmo que a verificação: linha sem PAN, sem validade ou sem CVV
     * é ignorada.
     *
     * @return array{lines:int, imported:int, duplicates:int, invalid:int, empty:int, expired:int}
     */
    public function importFile(string $path, int $batchSize = 5000): array
    {
        if ($batchSize < 1) {
            throw new InvalidArgumentException('batchSize deve ser >= 1');
        }
        if (!is_readable($path)) {
            throw new RuntimeException('arquivo não encontrado ou sem permissão de leitura');
        }

        $this->pdo->exec('PRAGMA journal_mode=WAL');
        $this->pdo->exec('PRAGMA synchronous=NORMAL');

        $now = self::nowUtc();
        $addedAt = $now->format('Y-m-d\TH:i:s.uP');
        $addedOn = $now->format('Y-m-d');
        $stats = [
            'lines' => 0,
            'imported' => 0,
            'duplicates' => 0,
            'invalid' => 0,
            'empty' => 0,
            'expired' => 0,
        ];
        $batch = [];

        $handle = fopen($path, 'rb');
        if ($handle === false) {
            throw new RuntimeException('falha ao abrir o arquivo');
        }

        try {
            $primeira = true;
            while (($line = fgets($handle)) !== false) {
                $stats['lines']++;
                if ($primeira) {
                    // Arquivos salvos no Windows costumam vir com BOM, que senão
                    // entraria na primeira linha do txt diário.
                    $line = (string) preg_replace('/^\xEF\xBB\xBF/', '', $line);
                    $primeira = false;
                }
                $stripped = trim($line);
                if ($stripped === '') {
                    $stats['empty']++;
                    continue;
                }

                try {
                    $entrada = self::parseEntry($stripped);
                } catch (InvalidNumberException) {
                    $stats['invalid']++;
                    if ($this->log !== null) {
                        // Entra no lote só para aparecer no txt, na ordem lida.
                        $batch[] = ['line' => $stripped, 'row' => null, 'expired' => false];
                    }
                    continue;
                }

                $digits = $entrada['pan'];
                $expired = self::isExpired($entrada['month'], $entrada['year']);
                if ($expired) {
                    $stats['expired']++;
                }

                $batch[] = [
                    'line' => $stripped,
                    'row' => [
                        $this->fingerprint($digits),
                        substr($digits, 0, 6),
                        substr($digits, -4),
                        $addedAt,
                        $addedOn,
                        $addedAt,
                        1,
                        strlen($digits),
                        self::formatCcFullFromEntry($entrada),
                    ],
                    'expired' => $expired,
                ];
                if (count($batch) >= $batchSize) {
                    [$inserted, $skipped] = $this->flushImportBatch($batch, $now);
                    $stats['imported'] += $inserted;
                    $stats['duplicates'] += $skipped;
                    $batch = [];
                }
            }
        } finally {
            fclose($handle);
        }

        if ($batch !== []) {
            [$inserted, $skipped] = $this->flushImportBatch($batch, $now);
            $stats['imported'] += $inserted;
            $stats['duplicates'] += $skipped;
        }

        return $stats;
    }

    /**
     * @param list<array{line:string,row:?array{0:string,1:string,2:string,3:string,4:string,5:string,6:int,7:int,8:string},expired:bool}> $batch
     * @return array{0:int,1:int}
     */
    private function flushImportBatch(array $batch, DateTimeImmutable $now): array
    {
        $validas = 0;
        $unicos = [];
        foreach ($batch as $entrada) {
            if ($entrada['row'] === null) {
                continue;
            }
            $validas++;
            $unicos[(string) $entrada['row'][0]] ??= $entrada;
        }

        $conhecidos = $this->existingFingerprints(array_keys($unicos));
        $novos = [];
        foreach ($unicos as $fingerprint => $entrada) {
            if (!isset($conhecidos[$fingerprint])) {
                $novos[$fingerprint] = true;
            }
        }

        $insert = $this->pdo->prepare(
            'INSERT INTO entries'
            . ' (fingerprint, bin, last4, added_at, added_on, last_seen_at,'
            . ' attempts, pan_length, cc_full)'
            . ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            . ' ON CONFLICT(fingerprint) DO UPDATE SET cc_full = excluded.cc_full'
            . ' WHERE excluded.cc_full != \'\''
        );
        $this->pdo->beginTransaction();
        try {
            foreach ($unicos as $entrada) {
                $insert->execute($entrada['row']);
            }
            $inserted = count($novos);
            $this->pdo->commit();
        } catch (Throwable $error) {
            $this->pdo->rollBack();
            throw $error;
        }

        if ($this->log !== null) {
            $marcadas = [];
            foreach ($batch as $entrada) {
                if ($entrada['row'] === null) {
                    $marcadas[] = [$entrada['line'], [DailyLog::MARK_INVALID]];
                    continue;
                }
                $extra = $entrada['expired'] ? [DailyLog::MARK_EXPIRED] : [];
                $fingerprint = (string) $entrada['row'][0];
                if (isset($novos[$fingerprint])) {
                    // Só a primeira ocorrência do lote é a que entrou.
                    unset($novos[$fingerprint]);
                    $marcadas[] = [$entrada['line'], [DailyLog::MARK_NEW, ...$extra]];
                } else {
                    $marcadas[] = [$entrada['line'], [DailyLog::MARK_KNOWN, ...$extra]];
                }
            }
            $this->log->appendMany($marcadas, $now);
        }

        return [$inserted, $validas - $inserted];
    }

    /**
     * @param list<string> $fingerprints
     * @return array<string,true>
     */
    private function existingFingerprints(array $fingerprints): array
    {
        $encontrados = [];
        foreach (array_chunk($fingerprints, 500) as $bloco) {
            $marcadores = implode(',', array_fill(0, count($bloco), '?'));
            $select = $this->pdo->prepare(
                "SELECT fingerprint FROM entries WHERE fingerprint IN ({$marcadores})"
            );
            $select->execute($bloco);
            foreach ($select->fetchAll() as $row) {
                $encontrados[(string) $row['fingerprint']] = true;
            }
        }

        return $encontrados;
    }

    /** @return list<array<string,mixed>> */
    public function recent(int $limit = 50): array
    {
        $select = $this->pdo->prepare(
            'SELECT * FROM entries ORDER BY last_seen_at DESC LIMIT ?'
        );
        $select->bindValue(1, max(1, $limit), PDO::PARAM_INT);
        $select->execute();
        $now = self::nowUtc();

        $rows = [];
        foreach ($select->fetchAll() as $row) {
            $addedAt = new DateTimeImmutable((string) $row['added_at']);
            $daysSince = self::daysBetween($addedAt, $now);
            $rows[] = [
                'masked' => $row['bin']
                    . str_repeat('*', ((int) ($row['pan_length'] ?? 16)) - 10)
                    . $row['last4'],
                'cc_full' => trim((string) ($row['cc_full'] ?? '')),
                'added_on' => $addedAt->format('Y-m-d'),
                'days_since_added' => $daysSince,
                'attempts' => (int) $row['attempts'],
                'last_seen_on' => (new DateTimeImmutable((string) $row['last_seen_at']))->format('Y-m-d'),
            ];
        }

        return $rows;
    }
}
