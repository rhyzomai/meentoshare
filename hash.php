<?php
// ============================================================
//  MEENTO — Hash Comment Store
//  Single-file PHP backend + frontend
// ============================================================

session_start();

// ── Directory setup ─────────────────────────────────────────
$hashesDir = __DIR__ . '/hashes/';
$usersDir  = __DIR__ . '/users/';
$sendDir   = __DIR__ . '/send/';

foreach ([$hashesDir, $usersDir, $sendDir] as $dir) {
    if (!is_dir($dir)) mkdir($dir, 0755, true);
}

// ── Salt for IP hashing — change this to something secret! ──
define('IP_SALT', 'meento_ip_salt_change_me_2024');

// ── Helpers ─────────────────────────────────────────────────

function jsonOut($ok, $msg, $extra = []) {
    echo json_encode(array_merge(['ok' => $ok, 'msg' => $msg], $extra));
    exit;
}

// Creates a file only if it does NOT exist yet (race-safe, atomic)
function createFileOnce($path, $content = '') {
    $fh = @fopen($path, 'x');      // 'x' = fail if file exists
    if ($fh === false) return false;
    fwrite($fh, $content);
    fclose($fh);
    return true;
}

// Overwrites (used only for the per-user send log)
function overwriteFile($path, $content) {
    $fh = @fopen($path, 'w');
    if ($fh === false) return false;
    fwrite($fh, $content);
    fclose($fh);
    return true;
}

// Best-effort client IP
function getClientIp() {
    foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $k) {
        if (!empty($_SERVER[$k])) {
            return trim(explode(',', $_SERVER[$k])[0]);
        }
    }
    return '0.0.0.0';
}

// Path to the empty lock file for this IP on today's date
function ipLockPath($usersDir) {
    $ip    = getClientIp();
    $day   = date('Ymd');   // e.g. 20260419 — resets every calendar day
    $token = hash('sha256', IP_SALT . $ip . $day);
    return $usersDir . 'ip_' . $token . '.lock';
}

// ── Route on ?action= or POST action ────────────────────────
$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action !== '') {
    header('Content-Type: application/json; charset=utf-8');
}

// ── REGISTER ────────────────────────────────────────────────
if ($action === 'register') {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');
    $mail     = trim($_POST['mail']     ?? '');
    $btc      = trim($_POST['btc']      ?? '');
    $pix      = trim($_POST['pix']      ?? '');

    if (!$username || !$password || !$mail)
        jsonOut(false, 'Username, password and e-mail are required.');
    if (!filter_var($mail, FILTER_VALIDATE_EMAIL))
        jsonOut(false, 'Please enter a valid e-mail address.');
    if (mb_strlen($username) < 3 || mb_strlen($username) > 32)
        jsonOut(false, 'Username must be between 3 and 32 characters.');
    if (mb_strlen($password) < 6)
        jsonOut(false, 'Password must be at least 6 characters.');

    $usernameHash = hash('sha256', strtolower($username));
    $userFile     = $usersDir . $usernameHash . '.json';

    if (file_exists($userFile))
        jsonOut(false, 'Username already taken.');

    $data = json_encode([
        'username'     => $usernameHash,              // hashed key for lookup
        'username_raw' => $username,                  // original for display
        'password'     => hash('sha256', $password),  // hashed for auth
        'mail'         => $mail,
        'btc'          => $btc,
        'pix'          => $pix,
        'created_at'   => date('Y-m-d H:i:s'),
    ], JSON_PRETTY_PRINT);

    if (!createFileOnce($userFile, $data))
        jsonOut(false, 'Could not create account (race condition or disk error).');

    jsonOut(true, 'Account created! You can now log in.');
}

// ── LOGIN ────────────────────────────────────────────────────
if ($action === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if (!$username || !$password)
        jsonOut(false, 'Username and password are required.');

    $usernameHash = hash('sha256', strtolower($username));
    $userFile     = $usersDir . $usernameHash . '.json';

    if (!file_exists($userFile))
        jsonOut(false, 'Invalid credentials.');

    $data = json_decode(file_get_contents($userFile), true);
    if (!$data || $data['password'] !== hash('sha256', $password))
        jsonOut(false, 'Invalid credentials.');

    $_SESSION['user']         = $usernameHash;
    $_SESSION['username_raw'] = $data['username_raw'] ?? $username;

    jsonOut(true, 'Logged in successfully.', [
        'userHash'    => $usernameHash,
        'displayName' => $data['username_raw'] ?? $username,
    ]);
}

// ── LOGOUT ───────────────────────────────────────────────────
if ($action === 'logout') {
    session_destroy();
    jsonOut(true, 'Logged out.');
}

// ── SESSION CHECK ────────────────────────────────────────────
if ($action === 'session') {
    if (!empty($_SESSION['user'])) {
        jsonOut(true, 'Authenticated.', [
            'userHash'    => $_SESSION['user'],
            'displayName' => $_SESSION['username_raw'] ?? '',
        ]);
    }
    jsonOut(false, 'Not logged in.');
}

// ── STORE HASH COMMENT ───────────────────────────────────────
if ($action === 'store') {
    $fileHash = trim($_POST['hash'] ?? '');
    $note     = trim($_POST['note'] ?? '');

    // Validate
    if (!preg_match('/^[a-f0-9]{64}$/', $fileHash))
        jsonOut(false, 'Invalid SHA-256 hash format.');
    if ($note === '')
        jsonOut(false, 'Comment cannot be empty.');
    if (mb_strlen($note) > 500)
        jsonOut(false, 'Comment exceeds 500 characters.');

    // ── IP rate-limit: one submission per IP per calendar day ─
    $lockPath = ipLockPath($usersDir);
    if (file_exists($lockPath))
        jsonOut(false, 'You have already submitted a comment today. Try again tomorrow.');

    // ── Hash comment must not already exist ───────────────────
    $hashFile = $hashesDir . $fileHash . '.txt';
    if (file_exists($hashFile))
        jsonOut(false, 'A comment for this hash already exists.');

    // ── Write comment ─────────────────────────────────────────
    if (!createFileOnce($hashFile, $note))
        jsonOut(false, 'Could not save comment (race condition or disk error).');

    // ── Create IP lock (empty file, daily reset) ──────────────
    createFileOnce($lockPath, '');

    // ── Log in user send-folder if authenticated ──────────────
    if (!empty($_SESSION['user'])) {
        $userSendDir = $sendDir . $_SESSION['user'] . '/';
        if (!is_dir($userSendDir)) mkdir($userSendDir, 0755, true);
        $logContent  = "hash: {$fileHash}\nnote: {$note}\nip: " . getClientIp() . "\nstored_at: " . date('Y-m-d H:i:s') . "\n";
        overwriteFile($userSendDir . $fileHash . '.txt', $logContent);
    }

    jsonOut(true, 'Comment saved successfully!');
}

// ── VIEW HASH (human-readable page) ─────────────────────────
if ($action === 'view') {
    $fileHash = trim($_GET['hash'] ?? '');
    if (!preg_match('/^[a-f0-9]{64}$/', $fileHash)) {
        header('Content-Type: text/plain'); echo 'Invalid hash.'; exit;
    }
    $hashFile = $hashesDir . $fileHash . '.txt';
    if (!file_exists($hashFile)) {
        header('Content-Type: text/plain'); echo 'Hash not found.'; exit;
    }
    $noteRaw  = file_get_contents($hashFile);
    $note     = htmlspecialchars($noteRaw, ENT_QUOTES, 'UTF-8');
    $emptyMsg = ($noteRaw === '') ? 'No comment was stored with this hash.' : '';
    header('Content-Type: text/html; charset=utf-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hash: {$fileHash}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  :root{--brand:#ff6a00;--bg:#fafafa;--border:#d8d8d8;--text:#1a1a1a;--muted:#666;--radius:8px;--shadow:0 2px 10px rgba(0,0,0,.08)}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
  header{background:var(--brand);padding:18px 24px;display:flex;align-items:center;box-shadow:var(--shadow)}
  .brand{color:#fff;font-weight:800;font-size:22px;letter-spacing:.5px}
  .brand span{font-weight:300;opacity:.75;font-size:14px;margin-left:6px}
  main{flex:1;max-width:760px;width:100%;margin:0 auto;padding:40px 24px}
  .lbl{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
  .hash-box{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;font-size:13px;word-break:break-all;padding:14px 16px;background:#fff;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:24px;color:var(--brand);box-shadow:var(--shadow)}
  .note-box{padding:20px;background:#fff;border:1px solid var(--border);border-radius:var(--radius);white-space:pre-wrap;line-height:1.7;font-size:15px;min-height:80px;box-shadow:var(--shadow)}
  .empty{color:var(--muted);font-style:italic}
  .back{display:inline-block;margin-top:28px;font-size:14px;color:var(--brand);text-decoration:none;font-weight:700;padding:10px 20px;border:2px solid var(--brand);border-radius:var(--radius);transition:background .2s,color .2s}
  .back:hover{background:var(--brand);color:#fff}
  footer{background:#1a1a1a;color:#aaa;text-align:center;padding:18px;font-size:14px}
  h1{font-size:26px;font-weight:800;margin-bottom:28px}h1 span{color:var(--brand)}
</style>
</head>
<body>
<header><div class="brand">Meento <span>file vault</span></div></header>
<main>
  <h1>Hash <span>record</span></h1>
  <div class="lbl">SHA-256</div>
  <div class="hash-box">{$fileHash}</div>
  <div class="lbl">Comment</div>
  <div class="note-box">{$note}<span class="empty">{$emptyMsg}</span></div>
  <a class="back" href="javascript:window.close()">&#8592; close tab</a>
</main>
<footer>Meento — all rights reserved</footer>
</body></html>
HTML;
    exit;
}

// ── LIST HASHES ──────────────────────────────────────────────
if ($action === 'list') {
    $files = glob($hashesDir . '*.txt') ?: [];
    $list  = [];
    foreach ($files as $f) {
        $name = basename($f, '.txt');
        if (!preg_match('/^[a-f0-9]{64}$/', $name)) continue;  // skip non-hash files
        $list[] = ['hash' => $name, 'note' => file_get_contents($f)];
    }
    usort($list, fn($a, $b) => strcmp($a['hash'], $b['hash']));
    echo json_encode(['ok' => true, 'hashes' => $list]);
    exit;
}

// ── Prepare PHP → JS state for the HTML page ────────────────
$preloadHash  = '';
$hashExists   = false;
$existingNote = '';
$ipBlocked    = file_exists(ipLockPath($usersDir));

if (isset($_GET['hash']) && preg_match('/^[a-f0-9]{64}$/', trim($_GET['hash']))) {
    $preloadHash = trim($_GET['hash']);
    $hashFile    = $hashesDir . $preloadHash . '.txt';
    if (file_exists($hashFile)) {
        $hashExists   = true;
        $existingNote = file_get_contents($hashFile);
    }
}

$jsPreloadHash  = json_encode($preloadHash);
$jsHashExists   = $hashExists ? 'true' : 'false';
$jsExistingNote = json_encode($existingNote);
$jsIpBlocked    = $ipBlocked  ? 'true' : 'false';

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Meento — hash comments</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  [hidden] { display: none !important; }
  html, body { height: 100%; }

  :root {
    --brand:   #ff6a00;
    --brand-d: #e05500;
    --bg:      #fafafa;
    --border:  #d8d8d8;
    --text:    #1a1a1a;
    --muted:   #666;
    --link:    #1a73e8;
    --green:   #1a8a4a;
    --red:     #c62828;
    --radius:  8px;
    --shadow:  0 2px 10px rgba(0,0,0,.08);
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: var(--text);
    background: var(--bg);
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  /* ── Header ── */
  .site-header {
    background: var(--brand);
    padding: 18px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
    box-shadow: var(--shadow);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .brand {
    color: #fff;
    font-weight: 800;
    font-size: 22px;
    letter-spacing: .5px;
    margin-right: 8px;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .brand span { font-weight: 300; opacity: .75; font-size: 14px; margin-left: 6px; }
  .site-header input[type="text"] {
    flex: 1;
    padding: 12px 16px;
    border: none;
    border-radius: var(--radius);
    font-size: 16px;
    outline: none;
    box-shadow: inset 0 1px 3px rgba(0,0,0,.1);
    min-width: 0;
  }
  .btn-search {
    background: #fff;
    color: var(--brand);
    border: none;
    padding: 12px 22px;
    font-size: 15px;
    font-weight: 700;
    border-radius: var(--radius);
    cursor: pointer;
    transition: transform .1s, box-shadow .2s;
    white-space: nowrap;
    flex-shrink: 0;
    font-family: inherit;
  }
  .btn-search:hover { box-shadow: 0 4px 12px rgba(0,0,0,.15); transform: translateY(-1px); }

  /* ── Main ── */
  main { flex: 1; max-width: 1100px; width: 100%; margin: 0 auto; padding: 40px 24px; }

  /* ── Hero ── */
  .hero {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 48px;
    align-items: center;
    margin-bottom: 40px;
  }
  .hero-art {
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #fff4ed 0%, #ffe0cc 100%);
    border-radius: 16px;
    padding: 48px 32px;
    min-height: 260px;
  }
  .hero-art svg { width: 180px; height: auto; }
  .hero-text h1 { font-size: 40px; line-height: 1.15; margin-bottom: 16px; }
  .hero-text h1 span { color: var(--brand); }
  .hero-text p { font-size: 18px; line-height: 1.6; color: #444; margin-bottom: 28px; }
  .hero-text code { background: #ffe8d6; color: var(--brand); padding: 1px 6px; border-radius: 4px; font-size: 15px; }

  /* ── Input group ── */
  .input-group { display: flex; gap: 10px; }
  .input-group input {
    flex: 1;
    padding: 14px 16px;
    border: 2px solid var(--border);
    border-radius: var(--radius);
    font-size: 13px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    outline: none;
    transition: border-color .2s;
    min-width: 0;
  }
  .input-group input:focus { border-color: var(--brand); }

  /* ── Buttons ── */
  .btn-primary {
    background: var(--brand);
    color: #fff;
    padding: 14px 24px;
    border-radius: var(--radius);
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    border: none;
    transition: background .2s, transform .1s, box-shadow .2s;
    box-shadow: 0 3px 14px rgba(255,106,0,.35);
    white-space: nowrap;
    flex-shrink: 0;
    font-family: inherit;
  }
  .btn-primary:hover:not(:disabled) {
    background: var(--brand-d);
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(255,106,0,.4);
  }
  .btn-primary:disabled { opacity: .5; cursor: not-allowed; transform: none !important; box-shadow: none !important; }
  .btn-cancel {
    background: transparent;
    color: var(--muted);
    border: 2px solid var(--border);
    padding: 10px 20px;
    border-radius: var(--radius);
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
    transition: border-color .15s, color .15s;
    font-family: inherit;
  }
  .btn-cancel:hover { border-color: var(--muted); color: var(--text); }

  /* ── Auth bar ── */
  .auth-bar {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
    min-height: 36px;
  }
  .user-badge {
    font-size: 12px;
    background: #fff0e6;
    border: 1px solid #ffd5b5;
    color: var(--brand);
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: 700;
  }
  .auth-link {
    font-size: 13px;
    color: var(--brand);
    cursor: pointer;
    background: none;
    border: none;
    font-weight: 700;
    padding: 0;
    text-decoration: underline;
    font-family: inherit;
  }

  /* ── Hash list ── */
  .section-head {
    font-size: 13px;
    font-weight: 700;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .section-head .count {
    background: var(--brand);
    color: #fff;
    border-radius: 20px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 800;
  }
  .search-meta { font-size: 12px; color: var(--muted); margin-left: auto; font-weight: 400; text-transform: none; letter-spacing: 0; }
  #hash-list { list-style: none; }
  .hash-entry {
    display: block;
    padding: 14px 4px;
    border-bottom: 1px solid var(--border);
    text-decoration: none;
    color: var(--text);
    transition: background .1s;
  }
  .hash-entry:last-child { border-bottom: none; }
  .hash-entry:hover { background: #fff8f4; }
  .hash-hex { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 12px; color: var(--brand); word-break: break-all; }
  .hash-note { font-size: 13px; color: var(--muted); margin-top: 4px; white-space: pre-wrap; word-break: break-word; }
  .hash-entry mark { background: #ffe0b2; color: inherit; border-radius: 2px; }
  .empty-state { text-align: center; color: var(--muted); padding: 40px 0; font-size: 16px; }
  .show-more-wrap { text-align: center; padding: 16px 0 8px; }

  /* ── Modals ── */
  .overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.45);
    z-index: 100;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .overlay.open { display: flex; }
  .modal {
    background: #fff;
    border-radius: 14px;
    box-shadow: 0 8px 40px rgba(0,0,0,.18);
    width: 100%;
    max-width: 540px;
    overflow: hidden;
  }
  .modal-header {
    background: var(--brand);
    padding: 20px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .modal-header h2 { color: #fff; font-size: 18px; font-weight: 800; }
  .modal-close {
    background: rgba(255,255,255,.25);
    border: none;
    color: #fff;
    font-size: 18px;
    line-height: 1;
    width: 32px; height: 32px;
    border-radius: 50%;
    cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: background .15s;
    font-family: inherit;
  }
  .modal-close:hover { background: rgba(255,255,255,.4); }
  .modal-body { padding: 24px; }
  .modal-footer { display: flex; justify-content: flex-end; gap: 10px; padding: 0 24px 24px; }

  /* Form fields */
  .field-label { font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin-bottom: 6px; display: block; }
  .hash-display {
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 11px; word-break: break-all;
    padding: 10px 14px;
    background: #fff8f4; border: 1px solid #ffd5b5;
    border-radius: var(--radius); color: var(--brand); margin-bottom: 20px;
  }
  .modal-body textarea {
    width: 100%; min-height: 120px; resize: vertical;
    padding: 12px 14px;
    border: 2px solid var(--border); border-radius: var(--radius);
    font-size: 14px; line-height: 1.6; font-family: inherit;
    outline: none; transition: border-color .2s;
  }
  .modal-body textarea:focus { border-color: var(--brand); }
  .modal-body textarea:disabled { background: #f5f5f5; color: var(--muted); cursor: not-allowed; }
  .char-count { text-align: right; font-size: 11px; color: var(--muted); margin-top: 4px; margin-bottom: 16px; }
  .char-count.over { color: var(--red); font-weight: 700; }

  /* Notices */
  .notice {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 12px 14px; border-radius: var(--radius);
    margin-bottom: 16px; font-size: 14px; line-height: 1.5;
    border-left: 4px solid transparent;
  }
  .notice.info    { background: #fff8f4; border-color: var(--brand); color: #a03000; }
  .notice.warning { background: #fffbf0; border-color: #e6a817;     color: #7a5500; }
  .notice .icon   { font-size: 18px; flex-shrink: 0; line-height: 1.4; }
  .existing-note {
    background: #fff8f4; border: 1px solid #ffd5b5;
    border-radius: var(--radius); padding: 12px 14px;
    font-size: 13px; color: #444; white-space: pre-wrap; line-height: 1.6;
  }

  /* Auth modal */
  .tabs { display: flex; border-bottom: 2px solid var(--border); margin-bottom: 20px; }
  .tab-btn {
    padding: 10px 20px; font-size: 14px; font-weight: 700; color: var(--muted);
    background: none; border: none; cursor: pointer;
    border-bottom: 3px solid transparent; margin-bottom: -2px;
    transition: color .15s, border-color .15s; font-family: inherit;
  }
  .tab-btn.active { color: var(--brand); border-color: var(--brand); }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }
  .form-field { margin-bottom: 16px; }
  .form-field label { display: block; font-size: 12px; font-weight: 700; color: var(--muted); margin-bottom: 6px; letter-spacing: .06em; text-transform: uppercase; }
  .form-field label em { font-weight: 400; text-transform: none; }
  .form-field input {
    width: 100%; padding: 11px 14px;
    border: 2px solid var(--border); border-radius: var(--radius);
    font-size: 14px; outline: none; transition: border-color .2s; font-family: inherit;
  }
  .form-field input:focus { border-color: var(--brand); }

  /* ── Toast ── */
  #toast-container {
    position: fixed; bottom: 24px; right: 24px; z-index: 999;
    display: flex; flex-direction: column; gap: 10px; pointer-events: none;
  }
  .toast {
    padding: 12px 20px; border-radius: var(--radius);
    font-size: 14px; font-weight: 600; color: #fff;
    box-shadow: 0 4px 16px rgba(0,0,0,.15);
    animation: toastIn .25s ease;
    max-width: 340px;
  }
  .toast.success { background: var(--green); }
  .toast.error   { background: var(--red); }
  .toast.info    { background: var(--brand); }
  .toast.warning { background: #e6a817; }
  @keyframes toastIn { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }

  /* ── Footer ── */
  footer { background: #1a1a1a; color: #aaa; text-align: center; padding: 18px; font-size: 14px; }

  /* ── Responsive ── */
  @media (max-width: 720px) {
    .hero { grid-template-columns: 1fr; text-align: center; }
    .hero-art { min-height: 160px; padding: 32px 24px; }
    .hero-art svg { width: 110px; }
    .hero-text h1 { font-size: 28px; }
    .hero-text p  { font-size: 16px; }
    .brand { font-size: 18px; }
    .site-header { flex-wrap: wrap; }
    .input-group { flex-direction: column; }
  }
</style>
</head>
<body>

<!-- ── Sticky Header ── -->
<header class="site-header">
  <div class="brand">Meento <span>file vault</span></div>
  <input id="searchInput" type="text" placeholder="Search stored hashes…" autocomplete="off" />
  <button type="button" class="btn-search" id="searchBtn">Search</button>
</header>

<main>

  <!-- Auth bar -->
  <div class="auth-bar">
    <span id="userBadge" class="user-badge" hidden></span>
    <button class="auth-link" id="authOpenBtn">Log in / Register</button>
    <button class="auth-link" id="logoutBtn" hidden>Log out</button>
  </div>

  <!-- Hero -->
  <section class="hero">
    <div class="hero-art">
      <svg viewBox="0 0 200 160" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <rect x="20" y="90" width="160" height="60" rx="14" fill="#ff6a00" opacity=".12"/>
        <rect x="36" y="100" width="128" height="40" rx="10" fill="#ff6a00" opacity=".18"/>
        <circle cx="100" cy="62" r="38" fill="#ff6a00" opacity=".15"/>
        <circle cx="60"  cy="76" r="24" fill="#ff6a00" opacity=".12"/>
        <circle cx="140" cy="74" r="28" fill="#ff6a00" opacity=".12"/>
        <line x1="88"  y1="50" x2="84"  y2="76" stroke="#ff6a00" stroke-width="4" stroke-linecap="round"/>
        <line x1="104" y1="50" x2="100" y2="76" stroke="#ff6a00" stroke-width="4" stroke-linecap="round"/>
        <line x1="80"  y1="58" x2="108" y2="58" stroke="#ff6a00" stroke-width="4" stroke-linecap="round"/>
        <line x1="78"  y1="68" x2="106" y2="68" stroke="#ff6a00" stroke-width="4" stroke-linecap="round"/>
      </svg>
    </div>
    <div class="hero-text">
      <h1>Comment on any<br><span>file hash.</span></h1>
      <p>
        Paste a <code>SHA-256</code> hash and attach a note to it —
        stored instantly, searchable forever.
        A <code>?hash=</code> link opens the form automatically.
      </p>
      <div class="input-group">
        <input type="text" id="hashLookupInput"
               placeholder="Paste a 64-char SHA-256 hash…"
               maxlength="64" spellcheck="false" autocomplete="off" />
        <button class="btn-primary" id="commentBtn">Comment</button>
      </div>
    </div>
  </section>

  <!-- Stored hashes list -->
  <div>
    <div class="section-head">
      <span>Stored hashes</span>
      <span class="count" id="result-count">…</span>
      <span class="search-meta" id="search-meta"></span>
    </div>
    <div id="hash-list"><div class="empty-state">◌ Loading…</div></div>
  </div>

</main>

<footer>Meento — all rights reserved</footer>

<!-- ══ Comment Modal ══ -->
<div class="overlay" id="comment-modal">
  <div class="modal">
    <div class="modal-header">
      <h2 id="comment-modal-title">Add comment</h2>
      <button class="modal-close" id="comment-close-btn" title="Close">✕</button>
    </div>
    <div class="modal-body">

      <span class="field-label">SHA-256 hash</span>
      <div class="hash-display" id="modal-hash-display">—</div>

      <!-- Already has a comment -->
      <div id="already-notice" hidden>
        <div class="notice info">
          <span class="icon">💬</span>
          <div>A comment already exists for this hash.</div>
        </div>
        <div class="existing-note" id="existing-note-text"></div>
      </div>

      <!-- IP blocked for today -->
      <div id="ip-blocked-notice" hidden>
        <div class="notice warning">
          <span class="icon">🚫</span>
          <div>You have already submitted a comment today. One submission per IP per day is allowed — try again tomorrow.</div>
        </div>
      </div>

      <!-- Comment textarea -->
      <div id="comment-form-area">
        <span class="field-label">Your comment</span>
        <textarea id="modal-note" maxlength="500" placeholder="Write your comment here…"></textarea>
        <div class="char-count" id="char-count">0 / 500</div>
      </div>

    </div>
    <div class="modal-footer">
      <button class="btn-cancel" id="comment-cancel-btn">Cancel</button>
      <button class="btn-primary" id="btn-store">Save comment</button>
    </div>
  </div>
</div>

<!-- ══ Auth Modal ══ -->
<div class="overlay" id="auth-modal">
  <div class="modal">
    <div class="modal-header">
      <h2>Account</h2>
      <button class="modal-close" id="auth-close-btn" title="Close">✕</button>
    </div>
    <div class="modal-body">
      <div class="tabs">
        <button class="tab-btn active" id="tab-login"    data-tab="login">Log in</button>
        <button class="tab-btn"        id="tab-register" data-tab="register">Register</button>
      </div>

      <div class="tab-panel active" id="panel-login">
        <div class="form-field">
          <label>Username</label>
          <input type="text" id="login-username" autocomplete="username" />
        </div>
        <div class="form-field">
          <label>Password</label>
          <input type="password" id="login-password" autocomplete="current-password" />
        </div>
      </div>

      <div class="tab-panel" id="panel-register">
        <div class="form-field">
          <label>Username <em>(3–32 chars)</em></label>
          <input type="text" id="reg-username" autocomplete="username" />
        </div>
        <div class="form-field">
          <label>Password <em>(min. 6 chars)</em></label>
          <input type="password" id="reg-password" autocomplete="new-password" />
        </div>
        <div class="form-field">
          <label>E-mail</label>
          <input type="email" id="reg-mail" autocomplete="email" />
        </div>
        <div class="form-field">
          <label>BTC address <em>(optional)</em></label>
          <input type="text" id="reg-btc" autocomplete="off" />
        </div>
        <div class="form-field">
          <label>Pix key <em>(optional)</em></label>
          <input type="text" id="reg-pix" autocomplete="off" />
        </div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn-cancel" id="auth-cancel-btn">Cancel</button>
      <button class="btn-primary" id="btn-login-submit">Log in</button>
      <button class="btn-primary" id="btn-register-submit" hidden>Register</button>
    </div>
  </div>
</div>

<!-- Toast container -->
<div id="toast-container"></div>

<script>
(function () {
  'use strict';

  // ── PHP-injected state ─────────────────────────────────────
  const PRELOAD_HASH  = <?= $jsPreloadHash ?>;
  const HASH_EXISTS   = <?= $jsHashExists ?>;
  const EXISTING_NOTE = <?= $jsExistingNote ?>;
  const IP_BLOCKED    = <?= $jsIpBlocked ?>;

  // ── State ──────────────────────────────────────────────────
  let allHashes   = [];
  let currentHash = '';
  const PAGE_SIZE = 10;
  const BASE_URL  = location.href.split('?')[0];

  // ── API ────────────────────────────────────────────────────
  async function api(params) {
    const fd = new FormData();
    for (const [k, v] of Object.entries(params)) fd.append(k, String(v));
    try {
      const r = await fetch(BASE_URL, { method: 'POST', body: fd });
      if (!r.ok) return { ok: false, msg: 'Server error ' + r.status };
      return await r.json();
    } catch {
      return { ok: false, msg: 'Network error — check your connection.' };
    }
  }

  // ── HTML escape ────────────────────────────────────────────
  function esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Toast ──────────────────────────────────────────────────
  function toast(msg, type = 'info') {
    const c  = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className   = 'toast ' + type;
    el.textContent = msg;
    c.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  // ── Modals ─────────────────────────────────────────────────
  function openModal(id)  { document.getElementById(id).classList.add('open'); }
  function closeModal(id) { document.getElementById(id).classList.remove('open'); }

  // Close on backdrop click
  document.querySelectorAll('.overlay').forEach(ov =>
    ov.addEventListener('click', e => { if (e.target === ov) ov.classList.remove('open'); })
  );

  // Wire close buttons
  document.getElementById('comment-close-btn').addEventListener('click',  () => closeModal('comment-modal'));
  document.getElementById('comment-cancel-btn').addEventListener('click', () => closeModal('comment-modal'));
  document.getElementById('auth-close-btn').addEventListener('click',     () => closeModal('auth-modal'));
  document.getElementById('auth-cancel-btn').addEventListener('click',    () => closeModal('auth-modal'));

  // ── Auth ───────────────────────────────────────────────────
  function setLoggedIn(yes, hash, name) {
    document.getElementById('userBadge').hidden   = !yes;
    document.getElementById('authOpenBtn').hidden =  yes;
    document.getElementById('logoutBtn').hidden   = !yes;
    if (yes) document.getElementById('userBadge').textContent = '● ' + (name || hash.slice(0,8) + '…');
  }

  document.getElementById('authOpenBtn').addEventListener('click', () => {
    switchTab('login'); openModal('auth-modal');
  });
  document.getElementById('logoutBtn').addEventListener('click', doLogout);
  document.getElementById('btn-login-submit').addEventListener('click', doLogin);
  document.getElementById('btn-register-submit').addEventListener('click', doRegister);

  // Tab switching — correct toggle of both panels AND both buttons
  document.querySelectorAll('.tab-btn').forEach(btn =>
    btn.addEventListener('click', () => switchTab(btn.dataset.tab))
  );

  function switchTab(name) {
    ['login', 'register'].forEach(t => {
      const on = t === name;
      document.getElementById('tab-' + t).classList.toggle('active', on);
      document.getElementById('panel-' + t).classList.toggle('active', on);
      document.getElementById('btn-' + t + '-submit').hidden = !on;
    });
  }

  async function doLogin() {
    const r = await api({
      action:   'login',
      username: document.getElementById('login-username').value.trim(),
      password: document.getElementById('login-password').value,
    });
    if (r.ok) {
      setLoggedIn(true, r.userHash, r.displayName);
      closeModal('auth-modal');
      toast('Welcome back, ' + (r.displayName || r.userHash.slice(0,8)) + '!', 'success');
      document.getElementById('login-username').value = '';
      document.getElementById('login-password').value = '';
    } else {
      toast(r.msg, 'error');
    }
  }

  async function doRegister() {
    const r = await api({
      action:   'register',
      username: document.getElementById('reg-username').value.trim(),
      password: document.getElementById('reg-password').value,
      mail:     document.getElementById('reg-mail').value.trim(),
      btc:      document.getElementById('reg-btc').value.trim(),
      pix:      document.getElementById('reg-pix').value.trim(),
    });
    toast(r.msg, r.ok ? 'success' : 'error');
    if (r.ok) switchTab('login');
  }

  async function doLogout() {
    await api({ action: 'logout' });
    setLoggedIn(false, null, null);
    toast('Logged out.', 'info');
  }

  // Enter key in login password triggers login
  document.getElementById('login-password').addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });

  // ── Comment modal ──────────────────────────────────────────
  function prepareCommentModal(hash, alreadyExists, existingNote, ipBlocked) {
    currentHash = hash;
    document.getElementById('modal-hash-display').textContent    = hash;
    document.getElementById('comment-modal-title').textContent   = alreadyExists ? 'Existing comment' : 'Add comment';

    const alreadyEl  = document.getElementById('already-notice');
    const ipEl       = document.getElementById('ip-blocked-notice');
    const formEl     = document.getElementById('comment-form-area');
    const btnStore   = document.getElementById('btn-store');

    // Reset all
    alreadyEl.hidden  = true;
    ipEl.hidden       = true;
    formEl.hidden     = false;
    btnStore.hidden   = false;
    btnStore.disabled = false;
    btnStore.textContent = 'Save comment';

    if (alreadyExists) {
      alreadyEl.hidden = false;
      document.getElementById('existing-note-text').textContent = existingNote || '(no text)';
      formEl.hidden   = true;
      btnStore.hidden = true;
      return;
    }

    if (ipBlocked) {
      ipEl.hidden       = false;
      btnStore.disabled = true;
    }

    document.getElementById('modal-note').value = '';
    updateCharCount();
  }

  function updateCharCount() {
    const len = document.getElementById('modal-note').value.length;
    const el  = document.getElementById('char-count');
    el.textContent = len + ' / 500';
    el.classList.toggle('over', len > 500);
  }
  document.getElementById('modal-note').addEventListener('input', updateCharCount);

  document.getElementById('btn-store').addEventListener('click', async function () {
    const note = document.getElementById('modal-note').value.trim();
    if (!note)       { toast('Please write a comment before saving.', 'warning'); return; }
    if (note.length > 500) { toast('Comment exceeds 500 characters.', 'error'); return; }

    this.disabled    = true;
    this.textContent = 'Saving…';

    const r = await api({ action: 'store', hash: currentHash, note });

    this.disabled    = false;
    this.textContent = 'Save comment';

    if (r.ok) {
      toast(r.msg, 'success');
      closeModal('comment-modal');
      await loadHashes();
    } else {
      toast(r.msg, 'error');
    }
  });

  // Open modal from the hero input field
  async function openCommentByInput() {
    const val = document.getElementById('hashLookupInput').value.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(val)) {
      toast('Please enter a valid 64-character hexadecimal SHA-256 hash.', 'error');
      return;
    }
    const found = allHashes.find(h => h.hash === val);
    prepareCommentModal(val, !!found, found ? found.note : '', IP_BLOCKED);
    openModal('comment-modal');
  }

  document.getElementById('commentBtn').addEventListener('click', openCommentByInput);
  document.getElementById('hashLookupInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') openCommentByInput();
  });

  // ── Hash list ──────────────────────────────────────────────
  async function loadHashes() {
    try {
      const r  = await fetch(BASE_URL + '?action=list');
      const d  = await r.json();
      allHashes = d.hashes || [];
    } catch {
      allHashes = [];
    }
    renderList(document.getElementById('searchInput').value);
  }

  function renderList(query) {
    const list = document.getElementById('hash-list');
    const cnt  = document.getElementById('result-count');
    const meta = document.getElementById('search-meta');
    const q    = query.trim().toLowerCase();

    const filtered = q
      ? allHashes.filter(h => h.hash.toLowerCase().includes(q) || h.note.toLowerCase().includes(q))
      : allHashes;

    cnt.textContent = allHashes.length + ' entr' + (allHashes.length === 1 ? 'y' : 'ies');

    if (filtered.length === 0) {
      meta.textContent = q ? 'No results for "' + query + '"' : '';
      list.innerHTML = '<div class="empty-state">◌ No hashes stored yet.</div>';
      return;
    }

    const showing   = filtered.slice(0, PAGE_SIZE);
    const remaining = filtered.length - showing.length;
    meta.textContent = q
      ? filtered.length + ' match' + (filtered.length === 1 ? '' : 'es') + ' · showing ' + showing.length
      : '';

    list.innerHTML = showing.map(h => rowHtml(h, q)).join('');

    if (remaining > 0) {
      const btn = document.createElement('div');
      btn.className = 'show-more-wrap';
      btn.innerHTML = '<button class="btn-primary" style="font-size:13px;padding:9px 20px">Show ' + remaining + ' more</button>';
      btn.querySelector('button').addEventListener('click', () => showAll(q));
      list.insertAdjacentElement('afterend', btn);
    }
  }

  function showAll(q) {
    const filtered = q
      ? allHashes.filter(h => h.hash.toLowerCase().includes(q) || h.note.toLowerCase().includes(q))
      : allHashes;
    document.getElementById('search-meta').textContent = q
      ? filtered.length + ' match' + (filtered.length === 1 ? '' : 'es') + ' · showing all'
      : 'Showing all ' + filtered.length;
    document.getElementById('hash-list').innerHTML = filtered.map(h => rowHtml(h, q)).join('');
  }

  function rowHtml(h, q) {
    const hexHl  = q ? hlMark(esc(h.hash), q) : esc(h.hash);
    const noteHl = h.note ? (q ? hlMark(esc(h.note), q) : esc(h.note)) : '';
    return '<a class="hash-entry" href="' + BASE_URL + '?action=view&hash=' +
      encodeURIComponent(h.hash) + '" target="_blank" rel="noopener">' +
      '<div class="hash-hex">' + hexHl + '</div>' +
      (noteHl ? '<div class="hash-note">' + noteHl + '</div>' : '') +
      '</a>';
  }

  function hlMark(text, q) {
    return text.replace(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'), 'gi'),
      m => '<mark>' + m + '</mark>');
  }

  // Search bar
  document.getElementById('searchInput').addEventListener('input',   e => renderList(e.target.value));
  document.getElementById('searchBtn').addEventListener('click',     () => renderList(document.getElementById('searchInput').value));
  document.getElementById('searchInput').addEventListener('keydown', e => { if (e.key === 'Enter') renderList(e.target.value); });

  // ── Init ───────────────────────────────────────────────────
  (async function init() {
    // Restore session silently
    const s = await api({ action: 'session' });
    if (s.ok) setLoggedIn(true, s.userHash, s.displayName);

    // Load hash list
    await loadHashes();

    // Auto-open comment modal when ?hash= is present and valid
    if (PRELOAD_HASH) {
      prepareCommentModal(PRELOAD_HASH, HASH_EXISTS, EXISTING_NOTE, IP_BLOCKED);
      openModal('comment-modal');
    }
  })();

})();
</script>
</body>
</html>