<?php
/**
 * register_server.php
 *
 * No GET params  → registers caller IP:52525 automatically, then outputs
 *                  the full contents of active_servers.txt (plain text,
 *                  one entry per line).
 *
 * ?server=<url>  → registers the custom URL and outputs only a plain-text
 *                  status line: ADDED, EXISTS, or ERROR: <reason>
 *
 * Uses fopen + flock (LOCK_EX / LOCK_SH) to avoid race conditions.
 */

// ─── Configuration ────────────────────────────────────────────────────────────
define('SERVERS_FILE', __DIR__ . '/active_servers.txt');
define('DAY_FILE',     __DIR__ . '/erase_active_servers.txt');
define('DEFAULT_PORT', '52525');
define('MAX_URL_LEN',  200);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function get_client_ip(): string
{
    foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

function validate_custom_url(string $url): bool
{
    if (strlen($url) === 0 || strlen($url) > MAX_URL_LEN) {
        return false;
    }
    return (bool) preg_match('/^[A-Za-z0-9.\-:\/]+$/', $url);
}

function read_lines($fh): array
{
    rewind($fh);
    $content = stream_get_contents($fh);
    if ($content === false || trim($content) === '') {
        return [];
    }
    return array_values(array_filter(
        array_map('trim', explode("\n", $content)),
        fn(string $l) => $l !== ''
    ));
}

function write_lines($fh, array $lines): void
{
    ftruncate($fh, 0);
    rewind($fh);
    if (!empty($lines)) {
        fwrite($fh, implode("\n", $lines) . "\n");
    }
}

/**
 * Registers $entry into active_servers.txt with daily-reset logic.
 * Returns one of: 'ADDED', 'EXISTS', or 'ERROR: <reason>'
 */
function register_entry(string $entry): string
{
    $today = date('Y-m-d');

    $dayFh = fopen(DAY_FILE, 'c+');
    if ($dayFh === false) {
        return 'ERROR: Cannot open day-stamp file.';
    }
    if (!flock($dayFh, LOCK_EX)) {
        fclose($dayFh);
        return 'ERROR: Cannot lock day-stamp file.';
    }

    rewind($dayFh);
    $storedDay  = trim(stream_get_contents($dayFh));
    $needsReset = ($storedDay !== $today);

    $serversFh = fopen(SERVERS_FILE, 'c+');
    if ($serversFh === false) {
        flock($dayFh, LOCK_UN);
        fclose($dayFh);
        return 'ERROR: Cannot open servers file.';
    }
    if (!flock($serversFh, LOCK_EX)) {
        fclose($serversFh);
        flock($dayFh, LOCK_UN);
        fclose($dayFh);
        return 'ERROR: Cannot lock servers file.';
    }

    if ($needsReset) {
        ftruncate($serversFh, 0);
        rewind($serversFh);
        ftruncate($dayFh, 0);
        rewind($dayFh);
        fwrite($dayFh, $today . "\n");
        fwrite($serversFh, $entry . "\n");
        $result = 'ADDED';
    } else {
        $lines = read_lines($serversFh);
        if (in_array($entry, $lines, true)) {
            $result = 'EXISTS';
        } else {
            $lines[] = $entry;
            write_lines($serversFh, $lines);
            $result = 'ADDED';
        }
    }

    flock($serversFh, LOCK_UN);
    fclose($serversFh);
    flock($dayFh, LOCK_UN);
    fclose($dayFh);

    return $result;
}

/**
 * Reads and returns all lines from active_servers.txt as plain text.
 */
function read_servers_file(): string
{
    if (!file_exists(SERVERS_FILE)) {
        return '';
    }
    $fh = fopen(SERVERS_FILE, 'r');
    if ($fh === false) {
        return 'ERROR: Cannot open servers file.';
    }
    if (!flock($fh, LOCK_SH)) {
        fclose($fh);
        return 'ERROR: Cannot lock servers file.';
    }
    $lines = read_lines($fh);
    flock($fh, LOCK_UN);
    fclose($fh);

    if (empty($lines)) {
        return '';
    }
    return implode("\n", $lines) . "\n";
}

// ─── Routing ──────────────────────────────────────────────────────────────────

header('Content-Type: text/plain; charset=UTF-8');

if (array_key_exists('server', $_GET)) {

    // ── ?server mode: register custom URL, output status only ─────────────────
    $custom = trim($_GET['server']);

    if ($custom === '') {
        echo 'ERROR: server parameter is empty.';
        exit;
    }

    if (!validate_custom_url($custom)) {
        echo 'ERROR: Invalid URL. Only letters, numbers, and . - : / are allowed (max ' . MAX_URL_LEN . ' chars).';
        exit;
    }

    echo register_entry($custom);

} else {

    // ── No params: auto-register IP:port, then show full list ─────────────────
    $entry = get_client_ip() . ':' . DEFAULT_PORT;
    register_entry($entry);   // result intentionally discarded
    echo read_servers_file();

}