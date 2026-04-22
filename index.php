<?php
// ─── Output buffer: prevents PHP warnings from corrupting JSON responses ──────
ob_start();

// ─── Configuration ────────────────────────────────────────────────────────────
define('UPLOAD_DIR',  __DIR__ . '/download/');
define('JSON_BASE',   __DIR__ . '/files');       // files.json, files_2.json, …
define('JSON_EXT',    '.json');
define('JSON_MAX',    512 * 1024);               // 500 KB per shard
define('MAX_SIZE',    1 * 1024 * 1024 * 1024);  // 1 GB max upload
define('FORBIDDEN',   ['php','phtml','php3','php4','php5','php7','phps','phar']);

// ─── JSON shard helpers ───────────────────────────────────────────────────────

/** Filesystem path for shard N.  1 → files.json, 2 → files_2.json, … */
function shard_path(int $n): string {
    return JSON_BASE . ($n === 1 ? '' : '_' . $n) . JSON_EXT;
}

/** Web-accessible filename for shard N (relative, for fetch() in JS). */
function shard_name(int $n): string {
    return 'files' . ($n === 1 ? '' : '_' . $n) . '.json';
}

/** Highest existing shard number (returns 1 even if nothing exists yet). */
function last_shard(): int {
    $n = 1;
    while (file_exists(shard_path($n + 1))) $n++;
    return $n;
}

/** Read one shard with a shared lock. Returns [] on missing / empty / invalid. */
function read_shard(int $n): array {
    $path = shard_path($n);
    if (!file_exists($path)) return [];
    $fh = fopen($path, 'r');
    if (!$fh) return [];
    flock($fh, LOCK_SH);
    $content = stream_get_contents($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    if (!trim($content)) return [];
    $data = json_decode($content, true);
    return is_array($data) ? $data : [];
}

/** Write $entries to shard $n with an exclusive lock. */
function write_shard(int $n, array $entries): void {
    $fh = fopen(shard_path($n), 'c+');
    if (!$fh) return;
    flock($fh, LOCK_EX);
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode(array_values($entries),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
}

/**
 * Append one entry to the right shard.
 * Starts a new shard whenever the current last one is at/over JSON_MAX bytes.
 * Returns the shard number where the entry was written.
 */
function append_entry(array $entry): int {
    $n    = last_shard();
    $path = shard_path($n);
    if (file_exists($path) && filesize($path) >= JSON_MAX) {
        $n++;
    }
    $entries   = read_shard($n);
    $entries[] = $entry;
    write_shard($n, $entries);
    return $n;
}

/**
 * Recursively scan UPLOAD_DIR, rename files to <sha256>.<ext>,
 * then distribute all entries across shards respecting JSON_MAX.
 */
function scan_and_rebuild(): void {
    ensure_dir();
    $all  = [];
    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(UPLOAD_DIR, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iter as $fi) {
        if (!$fi->isFile()) continue;
        $abs      = $fi->getPathname();
        $dir      = $fi->getPath() . DIRECTORY_SEPARATOR;
        $ext      = strtolower($fi->getExtension());
        $hash     = hash_file('sha256', $abs);
        $hashName = $ext !== '' ? "{$hash}.{$ext}" : $hash;
        $hashAbs  = $dir . $hashName;
        if ($fi->getFilename() !== $hashName) {
            if (!file_exists($hashAbs)) rename($abs, $hashAbs);
            else                        unlink($abs);
            $abs = $hashAbs;
        }
        $abs_norm  = str_replace('\\', '/', $abs);
        $base_norm = str_replace('\\', '/', UPLOAD_DIR);
        $relative  = ltrim(substr($abs_norm, strlen($base_norm)), '/');
        $all[] = [
            'original_name' => basename($relative),
            'filename'      => $relative,
            'date'          => date('Y-m-d H:i:s', filemtime($abs)),
            'filesize'      => filesize($abs),
            'filehash'      => $hash,
        ];
    }

    // Distribute into size-capped shards
    $shardNum  = 1;
    $shard     = [];
    $shardSize = 0;
    foreach ($all as $entry) {
        $sz = strlen(json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) + 4;
        if (!empty($shard) && ($shardSize + $sz) >= JSON_MAX) {
            write_shard($shardNum, $shard);
            $shardNum++;
            $shard     = [];
            $shardSize = 0;
        }
        $shard[]    = $entry;
        $shardSize += $sz;
    }
    write_shard($shardNum, $shard); // flush last (or only) shard

    // Remove stale shards left over from a previous larger index
    for ($k = $shardNum + 1; file_exists(shard_path($k)); $k++) {
        unlink(shard_path($k));
    }
}

/** Ensure shard 1 exists (triggers rebuild if missing/empty). */
function bootstrap(): void {
    if (!file_exists(shard_path(1)) || filesize(shard_path(1)) === 0) {
        scan_and_rebuild();
    }
}

function ensure_dir(): void {
    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0755, true);
}

function fmt_size(int $bytes): string {
    if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576)    return round($bytes / 1048576, 2)    . ' MB';
    if ($bytes >= 1024)       return round($bytes / 1024, 2)       . ' KB';
    return $bytes . ' B';
}

// ─── XHR detection ───────────────────────────────────────────────────────────
$isXhr = isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
         strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

// ─── Upload handler ───────────────────────────────────────────────────────────
$uploadError  = null;
$uploadedFile = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    ensure_dir();
    $file = $_FILES['file'];

    do {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $msgs = [
                UPLOAD_ERR_INI_SIZE   => 'File exceeds server limit.',
                UPLOAD_ERR_FORM_SIZE  => 'File exceeds form limit.',
                UPLOAD_ERR_PARTIAL    => 'Upload was partial.',
                UPLOAD_ERR_NO_FILE    => 'No file received.',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temp folder.',
                UPLOAD_ERR_CANT_WRITE => 'Cannot write to disk.',
                UPLOAD_ERR_EXTENSION  => 'Upload blocked by extension.',
            ];
            $uploadError = $msgs[$file['error']] ?? 'Unknown upload error.';
            break;
        }
        if ($file['size'] > MAX_SIZE) { $uploadError = 'File exceeds the 1 GB limit.'; break; }

        $originalName = basename($file['name']);
        $ext          = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if (in_array($ext, FORBIDDEN, true)) { $uploadError = 'PHP files are not allowed.'; break; }

        $hash     = hash_file('sha256', $file['tmp_name']);
        $hashName = $ext !== '' ? "{$hash}.{$ext}" : $hash;
        $dest     = UPLOAD_DIR . $hashName;

        if (file_exists($dest)) { $uploadError = 'This file already exists (identical content is already stored).'; break; }
        if (!move_uploaded_file($file['tmp_name'], $dest)) { $uploadError = 'Failed to save the file. Check folder permissions.'; break; }

        $newEntry = [
            'original_name' => $originalName,
            'filename'      => $hashName,
            'date'          => date('Y-m-d H:i:s'),
            'filesize'      => filesize($dest),
            'filehash'      => $hash,
        ];

        bootstrap();
        append_entry($newEntry);
        $uploadedFile = $newEntry;

    } while (false);

    // XHR: return JSON only
    if ($isXhr) {
        // Discard any stray PHP warnings/notices buffered above —
        // even one extra byte breaks JSON.parse() on the client.
        ob_end_clean();
        ini_set('display_errors', '0');

        header('Content-Type: application/json; charset=utf-8');
        if ($uploadError) {
            echo json_encode(['ok' => false, 'error' => $uploadError]);
        } else {
            $dir = dirname($_SERVER['REQUEST_URI']);
            $dir = ($dir === '/' || $dir === '\\') ? '' : rtrim($dir, '/');
            $bu = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                . '://' . $_SERVER['HTTP_HOST']
                . $dir . '/download/';
            $url_path = implode('/', array_map('rawurlencode', explode('/', $uploadedFile['filename'])));
            $sz = $uploadedFile['filesize'];
            echo json_encode([
                'ok'            => true,
                'original_name' => $uploadedFile['original_name'],
                'filename'      => $uploadedFile['filename'],
                'date'          => $uploadedFile['date'],
                'filesize'      => fmt_size($sz),
                'filehash'      => $uploadedFile['filehash'],
                'url'           => $bu . $url_path,
            ]);
        }
        exit;
    }
}

// ─── Bootstrap index & build page data ───────────────────────────────────────
bootstrap();

$_req_dir = dirname($_SERVER['REQUEST_URI']);
$_req_dir = ($_req_dir === '/' || $_req_dir === '\\') ? '' : rtrim($_req_dir, '/');
$base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
          . '://' . $_SERVER['HTTP_HOST']
          . $_req_dir . '/download/';

// Only shard 1 is injected into the page; JS fetches subsequent shards itself
$shard1 = read_shard(1);
$js_shard1 = json_encode(array_map(function($e) use ($base_url) {
    $url_path = implode('/', array_map('rawurlencode', explode('/', $e['filename'])));
    return [
        'original_name' => $e['original_name'] ?? $e['filename'],
        'filename'      => $e['filename'],
        'date'          => $e['date'],
        'filesize'      => fmt_size((int)$e['filesize']),
        'filehash'      => $e['filehash'],
        'url'           => $base_url . $url_path,
    ];
}, $shard1), JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES);

// Pass the base URL to JS so it can build shard URLs itself
$js_base_url = json_encode(
    (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
    . '://' . $_SERVER['HTTP_HOST']
    . $_req_dir
    . '/'
);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Meento</title>
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
  .search-bar {
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
  .brand { color:#fff; font-weight:800; font-size:22px; letter-spacing:.5px; margin-right:8px; white-space:nowrap; flex-shrink:0; }
  .brand span { font-weight:300; opacity:.75; font-size:14px; margin-left:6px; }
  .search-bar input[type="text"] {
    flex:1; padding:12px 16px; border:none; border-radius:var(--radius);
    font-size:16px; outline:none; box-shadow:inset 0 1px 3px rgba(0,0,0,.1); min-width:0;
  }
  .search-bar .btn-search {
    background:#fff; color:var(--brand); border:none; padding:12px 22px;
    font-size:15px; font-weight:700; border-radius:var(--radius);
    cursor:pointer; transition:transform .1s,box-shadow .2s; white-space:nowrap; flex-shrink:0;
  }
  .search-bar .btn-search:hover { box-shadow:0 4px 12px rgba(0,0,0,.15); transform:translateY(-1px); }

  /* ── Main ── */
  main { flex:1; max-width:1100px; width:100%; margin:0 auto; padding:40px 24px; }

  /* ── Hero ── */
  .hero { display:grid; grid-template-columns:1fr 1fr; gap:48px; align-items:center; margin-bottom:40px; }
  .hero.hidden-by-search { display:none; }
  .hero-art {
    display:flex; align-items:center; justify-content:center;
    background:linear-gradient(135deg,#fff4ed 0%,#ffe0cc 100%);
    border-radius:16px; padding:48px 32px; min-height:260px;
    transition:outline .15s,background .15s;
  }
  .hero-art svg { width:180px; height:auto; }
  .hero-art.drag-over { outline:3px dashed var(--brand); outline-offset:-6px; background:linear-gradient(135deg,#fff0e6 0%,#ffd5b5 100%); }
  .hero-text h1 { font-size:40px; line-height:1.15; margin-bottom:16px; color:var(--text); }
  .hero-text h1 span { color:var(--brand); }
  .hero-text p { font-size:18px; line-height:1.6; color:#444; margin-bottom:28px; }
  #fileInput { display:none; }
  .upload-btn {
    display:inline-block; background:var(--brand); color:#fff;
    padding:16px 32px; border-radius:var(--radius); font-size:17px; font-weight:700;
    cursor:pointer; border:none; transition:background .2s,transform .1s,box-shadow .2s;
    box-shadow:0 3px 14px rgba(255,106,0,.35);
  }
  .upload-btn:hover:not(:disabled) { background:var(--brand-d); transform:translateY(-2px); box-shadow:0 6px 20px rgba(255,106,0,.4); }
  .upload-btn:disabled { opacity:.65; cursor:default; }

  /* ── Notices ── */
  .notice {
    display:flex; align-items:flex-start; gap:12px; padding:16px 20px;
    border-radius:var(--radius); margin-bottom:28px; font-size:15px;
    line-height:1.5; border-left:4px solid transparent;
  }
  .notice.error   { background:#fff5f5; border-color:var(--red);   color:var(--red);   }
  .notice.success { background:#f0faf4; border-color:var(--green); color:var(--green); }
  .notice .icon   { font-size:20px; flex-shrink:0; line-height:1.4; }

  /* ── Progress ── */
  #progressWrap  { margin-bottom:24px; display:none; }
  #progressLabel { font-size:13px; color:var(--muted); margin-bottom:6px; }
  #progressBar   { width:100%; height:6px; background:var(--border); border-radius:99px; overflow:hidden; }
  #progressFill  { height:100%; width:0%; background:var(--brand); border-radius:99px; transition:width .1s linear; }

  /* ── Results ── */
  #listWrap { display:none; }
  .results { list-style:none; }
  .results li { position:relative; padding:14px 4px 14px 4px; padding-right:110px; border-bottom:1px solid var(--border); }
  .results li:last-child { border-bottom:none; }
  .results a.file-link { color:var(--link); text-decoration:none; font-size:16px; font-weight:600; word-break:break-all; }
  .results a.file-link:hover { text-decoration:underline; }
  .results .path-hint { font-size:12px; color:#999; margin-top:2px; }
  .results .meta { display:flex; flex-wrap:wrap; gap:6px 16px; margin-top:5px; }
  .results .meta span { font-size:12px; color:var(--muted); }
  .results .meta .hash { font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace; font-size:11px; word-break:break-all; }

  /* ── Comment button ── */
  .btn-comment {
    position:absolute; top:14px; right:4px;
    background:var(--brand); color:#fff; border:none;
    padding:5px 12px; font-size:12px; font-weight:700; border-radius:20px;
    cursor:pointer; text-decoration:none; white-space:nowrap;
    transition:background .15s,transform .1s,box-shadow .15s;
    box-shadow:0 2px 6px rgba(255,106,0,.3); letter-spacing:.02em;
  }
  .btn-comment:hover { background:var(--brand-d); transform:translateY(-1px); box-shadow:0 4px 10px rgba(255,106,0,.4); }

  /* ── Next link ── */
  #nextWrap { display:none; text-align:right; margin-top:16px; }
  #nextWrap a {
    color:var(--brand); font-size:13px; font-weight:600;
    text-decoration:none; letter-spacing:.02em;
  }
  #nextWrap a:hover { text-decoration:underline; }

  .empty { text-align:center; color:var(--muted); padding:40px 0; font-size:16px; }

  /* ── Footer ── */
  footer { background:#1a1a1a; color:#aaa; text-align:center; padding:18px; font-size:14px; }

  /* ── Responsive ── */
  @media (max-width:720px) {
    .hero { grid-template-columns:1fr; text-align:center; }
    .hero-art { min-height:160px; padding:32px 24px; }
    .hero-art svg { width:110px; }
    .hero-text h1 { font-size:28px; }
    .hero-text p  { font-size:16px; }
    .brand { font-size:18px; }
    .search-bar { flex-wrap:wrap; }
    .results li { padding-right:4px; }
    .btn-comment { position:static; display:inline-block; margin-top:10px; }
  }
</style>
</head>
<body>

<header class="search-bar">
  <a href="index.php" class="brand" style="color:#fff;text-decoration:none;">Meento</a>
  <input id="searchInput" type="text" placeholder="Search files…" autocomplete="off" />
  <button type="button" class="btn-search" id="searchBtn">Search</button>
</header>

<main>

  <?php if ($uploadError): ?>
  <div class="notice error" role="alert">
    <span class="icon">✕</span>
    <div><?= htmlspecialchars($uploadError) ?></div>
  </div>
  <?php endif; ?>

  <!-- Hero -->
  <section class="hero" id="hero">
    <div class="hero-art" id="dropZone">
      <svg viewBox="0 0 200 160" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <rect x="20" y="90" width="160" height="60" rx="14" fill="#ff6a00" opacity=".12"/>
        <rect x="36" y="100" width="128" height="40" rx="10" fill="#ff6a00" opacity=".18"/>
        <circle cx="100" cy="62" r="38" fill="#ff6a00" opacity=".15"/>
        <circle cx="60"  cy="76" r="24" fill="#ff6a00" opacity=".12"/>
        <circle cx="140" cy="74" r="28" fill="#ff6a00" opacity=".12"/>
        <line x1="100" y1="118" x2="100" y2="50" stroke="#ff6a00" stroke-width="5" stroke-linecap="round"/>
        <polyline points="82,68 100,48 118,68" fill="none" stroke="#ff6a00" stroke-width="5"
                  stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <div class="hero-text">
      <h1>Drop your file,<br><span>own the link.</span></h1>
      <p>
        Meento stores every upload under its <strong>SHA-256 hash</strong>,
        indexes it in <code>files.json</code>, and lets you search and
        annotate files instantly — zero dependencies, pure PHP.
      </p>
      <form method="POST" enctype="multipart/form-data" id="uploadForm">
        <input type="file" name="file" id="fileInput" />
        <button type="button" class="upload-btn" id="uploadBtn"> Upload File</button>
      </form>
    </div>
  </section>

  <!-- Progress -->
  <div id="progressWrap">
    <div id="progressLabel">Uploading… <span id="progressPct">0%</span></div>
    <div id="progressBar"><div id="progressFill"></div></div>
  </div>

  <!-- Results -->
  <div id="listWrap">
    <ul id="results" class="results"></ul>
    <div class="empty" id="emptyMsg" hidden>No matching files.</div>
    <div id="nextWrap"><a id="nextAnchor" href="#">Next →</a></div>
  </div>

</main>

<footer>Meento — all rights reserved</footer>

<script>
(function () {
  'use strict';

  // ── Constants injected by PHP ──────────────────────────────────────────────
  // Shard 1 entries, already formatted
  const SHARD1      = <?= $js_shard1 ?>;
  // Base URL of this directory (no trailing slash needed — we append filenames)
  const BASE_URL    = <?= $js_base_url ?>;   // e.g. "https://host/path/"

  // ── Shard URL builder (mirrors PHP shard_name()) ──────────────────────────
  // shard 1 → files.json, shard 2 → files_2.json, …
  function shardUrl(n) {
    return BASE_URL + (n === 1 ? 'files.json' : 'files_' + n + '.json');
  }

  // ── Download-URL builder for a file entry ─────────────────────────────────
  function fileUrl(filename) {
    return BASE_URL + 'download/' +
      filename.split('/').map(encodeURIComponent).join('/');
  }

  // ── Format a raw entry fetched from a shard JSON (no PHP fmt_size there) ──
  function formatEntry(raw) {
    const sz = raw.filesize;
    let fmtSz;
    if      (sz >= 1073741824) fmtSz = (sz/1073741824).toFixed(2) + ' GB';
    else if (sz >= 1048576)    fmtSz = (sz/1048576).toFixed(2)    + ' MB';
    else if (sz >= 1024)       fmtSz = (sz/1024).toFixed(2)       + ' KB';
    else                       fmtSz = sz + ' B';
    return {
      original_name: raw.original_name || raw.filename,
      filename:      raw.filename,
      date:          raw.date,
      filesize:      fmtSz,
      filehash:      raw.filehash,
      url:           fileUrl(raw.filename),
    };
  }

  // ── State ──────────────────────────────────────────────────────────────────
  let currentShard = 1;           // which shard is currently displayed
  let currentQuery = '';          // active search term
  let shardCache   = {};          // shard number → formatted entries[]
  shardCache[1]    = SHARD1;      // shard 1 is already formatted by PHP

  // ── DOM refs ──────────────────────────────────────────────────────────────
  const hero        = document.getElementById('hero');
  const listWrap    = document.getElementById('listWrap');
  const resultsList = document.getElementById('results');
  const emptyMsg    = document.getElementById('emptyMsg');
  const nextWrap    = document.getElementById('nextWrap');
  const nextAnchor  = document.getElementById('nextAnchor');
  const searchInput = document.getElementById('searchInput');
  const searchBtn   = document.getElementById('searchBtn');

  // ── Build one <li> from a formatted entry ─────────────────────────────────
  function buildLi(e) {
    const hasPath     = e.filename.includes('/');
    const commentHref = 'hash.php?hash=' + encodeURIComponent(e.filehash);
    const li = document.createElement('li');
    li.innerHTML =
      `<a class="btn-comment" href="${esc(commentHref)}" target="_blank" rel="noopener noreferrer">comment</a>` +
      `<a class="file-link"   href="${esc(e.url)}"        target="_blank" rel="noopener noreferrer">${esc(e.original_name)}</a>` +
      (hasPath ? `<div class="path-hint"> download/${esc(e.filename)}</div>` : '') +
      `<div class="meta">
         <span> ${esc(e.date)}</span>
         <span> ${esc(e.filesize)}</span>
         <span class="hash" title="SHA-256"> ${esc(e.filehash)}</span>
       </div>`;
    return li;
  }

  // ── Fetch a shard by number, using the cache ───────────────────────────────
  // Returns a Promise<entry[]>. Resolves to [] if the file doesn't exist (404).
  async function fetchShard(n) {
    if (shardCache[n] !== undefined) return shardCache[n];
    try {
      const res = await fetch(shardUrl(n), { cache: 'no-store' });
      if (!res.ok) { shardCache[n] = []; return []; }
      const raw = await res.json();
      shardCache[n] = Array.isArray(raw) ? raw.map(formatEntry) : [];
    } catch (_) {
      shardCache[n] = [];
    }
    return shardCache[n];
  }

  // ── Check whether the shard AFTER n exists ────────────────────────────────
  // Uses a HEAD request — no body downloaded.
  async function nextShardExists(n) {
    try {
      const res = await fetch(shardUrl(n + 1), { method: 'HEAD', cache: 'no-store' });
      return res.ok;
    } catch (_) { return false; }
  }

  // ── Render results for the current shard + query ──────────────────────────
  async function renderResults(q, shardN) {
    q      = (q      ?? currentQuery).trim().toLowerCase();
    shardN = shardN  ?? currentShard;

    currentQuery = q;
    currentShard = shardN;

    if (!q) {
      hero.classList.remove('hidden-by-search');
      listWrap.style.display = 'none';
      nextWrap.style.display = 'none';
      return;
    }

    hero.classList.add('hidden-by-search');

    const entries = await fetchShard(shardN);
    const matches = entries.filter(e =>
      e.original_name.toLowerCase().includes(q) ||
      e.filename.toLowerCase().includes(q)       ||
      e.filehash.toLowerCase().includes(q)
    );

    resultsList.innerHTML = '';
    listWrap.style.display = 'block';

    if (matches.length === 0) {
      emptyMsg.hidden = false;
      nextWrap.style.display = 'none';
      return;
    }

    emptyMsg.hidden = true;
    matches.forEach(e => resultsList.appendChild(buildLi(e)));

    // Check whether a next shard file exists — JS-only, no PHP involvement
    const hasNext = await nextShardExists(shardN);
    if (hasNext) {
      nextWrap.style.display = 'block';
      // Clicking Next loads the next shard in-page (no navigation)
      nextAnchor.onclick = async (ev) => {
        ev.preventDefault();
        await renderResults(currentQuery, currentShard + 1);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      };
    } else {
      nextWrap.style.display = 'none';
    }
  }

  // ── Hero visibility helper ─────────────────────────────────────────────────
  function setHeroVisible(v) {
    hero.classList.toggle('hidden-by-search', !v);
  }

  // ── Post-upload: inject a single highlighted result row ───────────────────
  function showUploadResult(entry) {
    // Insert into shard 1 cache so it shows in future searches
    if (!shardCache[1]) shardCache[1] = [];
    shardCache[1].unshift(entry);

    setHeroVisible(false);
    resultsList.innerHTML = '';
    emptyMsg.hidden = true;
    nextWrap.style.display = 'none';
    listWrap.style.display = 'block';

    const li = buildLi(entry);
    li.style.background  = '#f0faf4';
    li.style.borderLeft  = '4px solid #1a8a4a';
    li.style.paddingLeft = '12px';
    resultsList.appendChild(li);
  }

  // ── Upload ─────────────────────────────────────────────────────────────────
  const uploadBtn    = document.getElementById('uploadBtn');
  const fileInput    = document.getElementById('fileInput');
  const uploadForm   = document.getElementById('uploadForm');
  const dropZone     = document.getElementById('dropZone');
  const progressWrap = document.getElementById('progressWrap');
  const progressFill = document.getElementById('progressFill');
  const progressPct  = document.getElementById('progressPct');

  uploadBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) submitUpload(fileInput.files[0]);
  });
  ['dragenter','dragover'].forEach(ev =>
    dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.add('drag-over'); })
  );
  ['dragleave','drop'].forEach(ev =>
    dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.remove('drag-over'); })
  );
  dropZone.addEventListener('drop', e => {
    const f = e.dataTransfer.files[0];
    if (f) submitUpload(f);
  });

  function submitUpload(file) {
    if (file.size > 1073741824) { showNotice('error', 'File exceeds the 1 GB limit.'); return; }
    const ext = file.name.split('.').pop().toLowerCase();
    if (['php','phtml','php3','php4','php5','php7','phps','phar'].includes(ext)) {
      showNotice('error', 'PHP files are not allowed.'); return;
    }
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;

    const fd  = new FormData(uploadForm);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', window.location.href, true);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

    xhr.upload.addEventListener('progress', ev => {
      if (ev.lengthComputable) {
        const pct = Math.round(ev.loaded / ev.total * 100);
        progressFill.style.width = pct + '%';
        progressPct.textContent  = pct + '%';
      }
    });
    xhr.addEventListener('loadstart', () => {
      progressWrap.style.display = 'block';
      uploadBtn.disabled = true;
      uploadBtn.textContent = '⏳ Uploading…';
    });
    xhr.addEventListener('load', () => {
      progressWrap.style.display = 'none';
      uploadBtn.disabled = false;
      uploadBtn.textContent = '⬆ Upload File';
      fileInput.value = '';

      let resp;
      try { resp = JSON.parse(xhr.responseText); }
      catch(e) { showNotice('error', 'Unexpected server response.'); return; }

      if (!resp.ok) { showNotice('error', resp.error || 'Upload failed.'); return; }

      clearNotices();
      showUploadResult(resp);
      searchInput.value = '';
      currentQuery = '';
      currentShard = 1;
      // Bust the shard 1 cache so the next search re-fetches the updated file
      delete shardCache[1];
      shardCache[1] = undefined;
    });
    xhr.addEventListener('error', () => {
      progressWrap.style.display = 'none';
      uploadBtn.disabled = false;
      uploadBtn.textContent = '⬆ Upload File';
      showNotice('error', 'Network error during upload.');
    });
    xhr.send(fd);
  }

  // ── Notice helpers ─────────────────────────────────────────────────────────
  function showNotice(type, msg) {
    clearNotices();
    const div = document.createElement('div');
    div.className = 'notice ' + type;
    div.dataset.dynamic = '1';
    div.innerHTML = `<span class="icon">${type === 'error' ? '✕' : '✓'}</span><div>${esc(msg)}</div>`;
    document.querySelector('main').prepend(div);
  }
  function clearNotices() {
    document.querySelectorAll('.notice[data-dynamic]').forEach(n => n.remove());
  }

  // ── Escape helper ──────────────────────────────────────────────────────────
  function esc(str) {
    return String(str)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Search listeners ───────────────────────────────────────────────────────
  searchInput.addEventListener('input', e => {
    currentShard = 1; // reset to shard 1 on every new keystroke
    renderResults(e.target.value, 1);
  });
  searchBtn.addEventListener('click', () => {
    currentShard = 1;
    renderResults(searchInput.value, 1);
  });
  searchInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') { currentShard = 1; renderResults(searchInput.value, 1); }
  });

})();
</script>
</body>
</html>