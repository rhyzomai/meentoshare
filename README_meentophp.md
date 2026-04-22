# Meento PHP

A lightweight, zero-dependency file hosting application written in pure PHP. Upload any file, get a permanent shareable link, and search your entire library instantly — no database required.

---

## Features

- **One-file deployment** — the entire application lives in a single `index.php`.
- **SHA-256 content addressing** — every uploaded file is renamed to its SHA-256 hash, eliminating duplicates automatically.
- **Sharded JSON index** — the file catalogue is stored in size-capped JSON shards (`files.json`, `files_2.json`, …) instead of a database. Each shard is capped at 500 KB.
- **Drag-and-drop uploads** — drop a file onto the hero area or click the upload button; a real-time progress bar tracks the transfer.
- **Live search** — search by filename, path, or SHA-256 hash across all shards without a page reload.
- **Comment/annotation links** — each file entry links to a `hash.php` page for comments or annotations.
- **Responsive UI** — works on desktop and mobile browsers.
- **No framework, no Composer** — runs on any standard PHP host.

---

## Requirements

- PHP 7.4 or higher
- Web server with `mod_rewrite` (Apache) or equivalent (Nginx, Caddy)
- Write permission on the project directory (for `download/` and JSON shards)

---

## Installation

1. Copy `index.php` to your web root or a subdirectory.
2. Make sure the web server can write to that directory:
   ```bash
   chmod 755 /var/www/html/meento
   ```
3. Open the URL in your browser. The application will create the `download/` folder and the first `files.json` shard automatically on the first request.

---

## Directory Structure

```
meento/
├── index.php          # Main application (upload, search, UI)
├── hash.php           # (Optional) Per-file comment/annotation page
├── files.json         # Shard 1 of the file index (auto-created)
├── files_2.json       # Shard 2, created when shard 1 reaches 500 KB
└── download/          # Uploaded files, named <sha256>.<ext>
```

---

## Configuration

All settings are defined as constants at the top of `index.php`:

| Constant    | Default                   | Description                                      |
|-------------|---------------------------|--------------------------------------------------|
| `UPLOAD_DIR`| `__DIR__ . '/download/'`  | Directory where uploaded files are stored        |
| `JSON_BASE` | `__DIR__ . '/files'`      | Base path for JSON index shards                  |
| `JSON_EXT`  | `.json`                   | Extension for shard files                        |
| `JSON_MAX`  | `512 * 1024` (500 KB)     | Maximum size per shard before a new one is created |
| `MAX_SIZE`  | `1 * 1024 * 1024 * 1024` (1 GB) | Maximum allowed upload size               |
| `FORBIDDEN` | `php, phtml, php3, …`    | File extensions that are blocked from uploading  |

---

## How It Works

### Uploading a File

1. The user selects or drops a file onto the page.
2. The file is sent to the server via an AJAX `XMLHttpRequest` (no page reload).
3. PHP validates the file: checks size limit, blocks forbidden extensions (PHP files), and checks for duplicates via SHA-256 hash.
4. The file is saved to `download/<sha256>.<ext>`.
5. A metadata entry (`original_name`, `filename`, `date`, `filesize`, `filehash`) is appended to the current JSON shard.
6. The UI highlights the newly uploaded file and displays its download link.

### Searching Files

1. The user types in the search bar.
2. JavaScript filters the in-memory shard 1 cache and fetches additional shards on demand using `fetch()`.
3. Results are matched against filename, path, and SHA-256 hash.
4. If more results exist in the next shard, a **Next →** button appears for pagination (no page reload).

### JSON Sharding

- The index is split across multiple JSON files to keep each file manageable.
- Shard 1 (`files.json`) is embedded directly into the page on load; subsequent shards are fetched lazily by the browser only when needed.
- When a shard reaches 500 KB, the next upload automatically starts a new shard (`files_2.json`, `files_3.json`, …).

### Duplicate Detection

- Before saving, the application computes the SHA-256 hash of the incoming file.
- If a file with the same hash already exists in `download/`, the upload is rejected with a clear error message.

---

## Security

- **Forbidden extensions**: PHP and related executable extensions (`php`, `phtml`, `php3`, `php4`, `php5`, `php7`, `phps`, `phar`) are blocked server-side and validated client-side before upload.
- **Output escaping**: All file metadata rendered in HTML is escaped to prevent XSS.
- **File locking**: JSON shards are read and written with `flock()` shared/exclusive locks to prevent data corruption under concurrent requests.
- **No arbitrary execution**: Uploaded files are stored under their hash name and served as static downloads.

> **Recommendation**: Configure your web server to serve the `download/` directory with `Content-Disposition: attachment` and disable PHP execution inside it for extra safety.

---

## Rebuild Index

If the JSON index becomes out of sync with the actual files on disk (e.g., after a manual file operation), you can trigger a rebuild. The application will automatically rebuild the index on startup if shard 1 is missing or empty. To force a rebuild manually, delete `files.json` and reload the page.

During a rebuild, the application:
1. Scans all files recursively inside `download/`.
2. Renames any file not already named by its hash to `<sha256>.<ext>`.
3. Redistributes all entries across fresh shards respecting the `JSON_MAX` size limit.
4. Removes any stale extra shards from a previous larger index.

---

## License

© Meento — All rights reserved.
