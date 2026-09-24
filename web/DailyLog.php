<?php

declare(strict_types=1);

/**
 * Registro diário em texto: um .txt por dia com tudo que passou pela verificação.
 *
 * Espelha antiretest/daily_log.py — mesma pasta, mesmo nome de arquivo e mesmo
 * formato, então Python e PHP escrevem no mesmo txt do dia.
 */
final class DailyLog
{
    public const DEFAULT_DIR_NAME = 'registros';

    public const MARK_NEW = 'NOVO';
    public const MARK_KNOWN = 'REPETIDO';
    public const MARK_INVALID = 'INVALIDO';
    public const MARK_EXPIRED = 'VENCIDO';
    public const MARKS = [self::MARK_NEW, self::MARK_KNOWN, self::MARK_INVALID, self::MARK_EXPIRED];

    /**
     * As marcas entram como campos extras no fim da linha ("...|NOVO|VENCIDO").
     * Campos extras são descartados na leitura, então o txt continua reimportável.
     */
    public const MARK_SEPARATOR = '|';

    private string $directory;

    public function __construct(string $directory)
    {
        $this->directory = rtrim($directory, '/\\');
    }

    /** Pasta registros/ ao lado do banco, para os dois andarem juntos. */
    public static function defaultDirFor(string $dbPath): string
    {
        return dirname($dbPath) . DIRECTORY_SEPARATOR . self::DEFAULT_DIR_NAME;
    }

    /**
     * Fuso do corte do dia: ANTIRETEST_TZ ou o fuso configurado no PHP.
     *
     * O date.timezone do php.ini costuma não ser o do computador (no XAMPP vem
     * Europe/Berlin), então defina ANTIRETEST_TZ para casar com o lado Python.
     */
    public static function zone(): DateTimeZone
    {
        $nome = (string) (getenv('ANTIRETEST_TZ') ?: '');
        if ($nome !== '') {
            try {
                return new DateTimeZone($nome);
            } catch (Exception) {
                // nome inválido: fica o fuso do próprio PHP
            }
        }

        return new DateTimeZone(date_default_timezone_get());
    }

    public function directory(): string
    {
        return $this->directory;
    }

    public function pathFor(DateTimeImmutable $day): string
    {
        return $this->directory . DIRECTORY_SEPARATOR
            . $day->setTimezone(self::zone())->format('Y-m-d') . '.txt';
    }

    public function append(string $line, ?string $mark = null, ?DateTimeImmutable $now = null): string
    {
        return $this->appendMany([[$line, $mark]], $now);
    }

    /**
     * Uma linha com várias marcas ("...|NOVO|VENCIDO").
     *
     * @param list<string> $marks
     */
    public function appendMarks(string $line, array $marks, ?DateTimeImmutable $now = null): string
    {
        return $this->appendMany([[$line, $marks]], $now);
    }

    /**
     * Grava vários pares [linha, marcas], abrindo o arquivo uma única vez.
     *
     * @param iterable<array{0:string,1:list<string>|string|null}> $entries
     */
    public function appendMany(iterable $entries, ?DateTimeImmutable $now = null): string
    {
        $momento = $now ?? new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $path = $this->pathFor($momento);

        $conteudo = '';
        foreach ($entries as [$line, $marks]) {
            // Uma entrada nunca pode virar duas linhas no txt: quebras viram espaço.
            $texto = trim((string) preg_replace('/[\r\n]+/', ' ', (string) $line));
            if ($texto === '') {
                continue;
            }
            foreach (self::asMarks($marks) as $marca) {
                $texto .= self::MARK_SEPARATOR . $marca;
            }
            $conteudo .= $texto . "\n";
        }
        if ($conteudo === '') {
            return $path;
        }

        if (!is_dir($this->directory)
            && !mkdir($this->directory, 0775, true)
            && !is_dir($this->directory)
        ) {
            throw new RuntimeException('não foi possível criar a pasta ' . $this->directory);
        }
        if (file_put_contents($path, $conteudo, FILE_APPEND | LOCK_EX) === false) {
            throw new RuntimeException('não foi possível escrever em ' . $path);
        }

        return $path;
    }

    /**
     * Aceita uma marca só, várias, ou nenhuma.
     *
     * @param list<string>|string|null $marks
     * @return list<string>
     */
    private static function asMarks(array|string|null $marks): array
    {
        if ($marks === null || $marks === '') {
            return [];
        }
        if (is_string($marks)) {
            return [$marks];
        }

        return array_values(array_filter($marks, static fn($marca): bool => (string) $marca !== ''));
    }

    /**
     * Separa a linha das marcas no fim; lista vazia quando não houver.
     *
     * @return array{0:string,1:list<string>}
     */
    public static function splitMarks(string $line): array
    {
        $restante = $line;
        $marcas = [];
        while (true) {
            $corte = strrpos($restante, self::MARK_SEPARATOR);
            if ($corte === false) {
                return [$restante, array_reverse($marcas)];
            }
            $sufixo = trim(substr($restante, $corte + 1));
            if (!in_array($sufixo, self::MARKS, true)) {
                return [$restante, array_reverse($marcas)];
            }
            $marcas[] = $sufixo;
            $restante = substr($restante, 0, $corte);
        }
    }

    /**
     * Linhas gravadas num dia, com a marca, na ordem em que entraram.
     *
     * @return list<string>
     */
    public function linesFor(DateTimeImmutable $day): array
    {
        $path = $this->pathFor($day);
        if (!is_file($path)) {
            return [];
        }
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return [];
        }
        $linhas = [];
        try {
            while (($linha = fgets($handle)) !== false) {
                $texto = trim($linha);
                if ($texto !== '') {
                    $linhas[] = $texto;
                }
            }
        } finally {
            fclose($handle);
        }

        return $linhas;
    }

    /**
     * Mesmo conteúdo de linesFor, com as marcas já separadas.
     *
     * @return list<array{0:string,1:list<string>}>
     */
    public function entriesFor(DateTimeImmutable $day): array
    {
        return array_map([self::class, 'splitMarks'], $this->linesFor($day));
    }

    /**
     * Dias que já têm arquivo (AAAA-MM-DD), do mais antigo para o mais recente.
     *
     * @return list<string>
     */
    public function days(): array
    {
        if (!is_dir($this->directory)) {
            return [];
        }
        $dias = [];
        foreach (glob($this->directory . DIRECTORY_SEPARATOR . '*.txt') ?: [] as $path) {
            $nome = basename($path, '.txt');
            $data = DateTimeImmutable::createFromFormat('Y-m-d', $nome, new DateTimeZone('UTC'));
            if ($data !== false && $data->format('Y-m-d') === $nome) {
                $dias[] = $nome;
            }
        }
        sort($dias);

        return $dias;
    }

    /**
     * Quantas linhas de cada marca num dia.
     *
     * @return array{total:int, NOVO:int, REPETIDO:int, INVALIDO:int, VENCIDO:int}
     */
    public function tally(DateTimeImmutable $day): array
    {
        $resumo = ['total' => 0];
        foreach (self::MARKS as $marca) {
            $resumo[$marca] = 0;
        }
        foreach ($this->entriesFor($day) as [$linha, $marcas]) {
            $resumo['total']++;
            foreach ($marcas as $marca) {
                $resumo[$marca]++;
            }
        }

        return $resumo;
    }
}
