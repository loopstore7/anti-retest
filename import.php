<?php

declare(strict_types=1);

/**
 * Importa db.txt (ou outro arquivo) para o SQLite compartilhado com a web.
 *
 * Uso:
 *   php import.php
 *   php import.php db.txt
 *   php import.php --db=antiretest.db --batch-size=5000 db.txt
 *   php import.php --log-dir=registros --no-log db.txt
 */

require __DIR__ . DIRECTORY_SEPARATOR . 'web' . DIRECTORY_SEPARATOR . 'AntiRetest.php';

$args = array_slice($argv, 1);
$dbPath = getenv('ANTIRETEST_DB') ?: __DIR__ . DIRECTORY_SEPARATOR . 'antiretest.db';
$batchSize = 5000;
$seedPath = __DIR__ . DIRECTORY_SEPARATOR . 'db.txt';
$logDir = null;
$semLog = false;

foreach ($args as $arg) {
    if (str_starts_with($arg, '--db=')) {
        $dbPath = substr($arg, 5);
        continue;
    }
    if (str_starts_with($arg, '--batch-size=')) {
        $batchSize = (int) substr($arg, 13);
        continue;
    }
    if (str_starts_with($arg, '--log-dir=')) {
        $logDir = substr($arg, 10);
        continue;
    }
    if ($arg === '--no-log') {
        $semLog = true;
        continue;
    }
    if (!str_starts_with($arg, '--')) {
        $seedPath = $arg;
    }
}

$logDir = $semLog ? null : ($logDir ?? DailyLog::defaultDirFor($dbPath));

if (!is_file($seedPath)) {
    fwrite(STDERR, "arquivo não encontrado: {$seedPath}\n");
    exit(2);
}

if ($batchSize < 1) {
    fwrite(STDERR, "batch-size deve ser >= 1\n");
    exit(2);
}

try {
    $engine = new AntiRetest($dbPath, $logDir);
    fwrite(STDERR, "importando de {$seedPath}...\n");
    $result = $engine->importFile($seedPath, $batchSize);
    fwrite(
        STDOUT,
        sprintf(
            "%d importado(s) · %d duplicado(s) · %d inválido(s) · %d vencido(s)"
            . " · %d linha(s) lida(s)\n",
            $result['imported'],
            $result['duplicates'],
            $result['invalid'],
            $result['expired'],
            $result['lines']
        )
    );
} catch (Throwable $error) {
    fwrite(STDERR, 'falha na importação: ' . $error->getMessage() . "\n");
    exit(1);
}
