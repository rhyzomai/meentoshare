# Ant Meento GUI v4.0

A peer-to-peer (P2P) file sharing desktop application built in Java with a dark-themed Swing GUI. It combines decentralized file exchange, PKI-based identity, a local blockchain ledger, DHT peer bootstrapping, and direct HTTP file downloading — all in a single self-contained `.java` file.

---

## Features

- **P2P File Sharing** — share and receive files directly with other peers over TCP on a configurable port (default: `52525`).
- **PKI Identity** — each node automatically generates a 2048-bit RSA key pair on first launch. Your identity is persistent across sessions and identified by an 8-character fingerprint.
- **Blockchain Ledger** — every P2P file transfer is recorded as a signed, proof-of-work block on a local blockchain. Blocks are broadcast to known peers and validated against the chain.
- **DHT Bootstrap** — on startup, the application fetches peer lists from multiple public bootstrap URLs and merges discovered peers into `servers.txt` automatically (non-blocking, threaded).
- **HTTP Direct Download** — URLs in `servers.txt` ending with a recognized file extension (e.g., `.jpg`, `.mp4`, `.pdf`, `.zip`) are treated as direct HTTP download targets during sync. These downloads are silent and do not create blockchain records.
- **Receive Mode Toggle** — you can disable incoming file pushes at any time from the UI.
- **Drag & Drop** — files can be dragged and dropped into the application to share them.

---

## Requirements

- **Java 8 or later** (uses standard `javax.swing`, `java.security`, `java.net`)
- No external libraries or build tools required

---

## Getting Started

### Compile

```bash
javac AntMeentoGui.java
```

### Run

```bash
java AntMeentoGui
```

On first launch, the application will:

1. Create the required directories (`download/`, `blockchain/`, `identity/`).
2. Generate a new RSA key pair and save it to `identity/private.key` and `identity/public.key`.
3. Start listening on port `52525`.
4. Bootstrap DHT by contacting the configured public peer-list URLs.

---

## Directory Structure

```
.
├── AntMeentoGui.java       # Source file
├── servers.txt             # Peer list (managed automatically)
├── download/               # Shared and received files
├── blockchain/             # Block records (one .json file per block)
│   └── chain.index         # Blockchain index
└── identity/
    ├── private.key         # Your RSA private key (Base64)
    └── public.key          # Your RSA public key (Base64)
```

---

## Peer Entry Formats (`servers.txt`)

Each line in `servers.txt` can be one of:

| Format | Behavior |
|---|---|
| `host:52525` | Standard P2P peer |
| `hostname` | P2P peer on the default port |
| `https://host:52525/path` | P2P peer accessed via URL with explicit P2P port |
| `https://host/file.jpg` | Direct HTTP file download (no blockchain record) |
| `https://host/servers.txt` | Remote peer list — fetched and merged at sync time |

---

## UI Tabs

### My Files
Lists all files in the `download/` directory with name, size, and modification date. Use the **SYNC ALL** button to synchronize with all known peers and HTTP entries.

### Servers / DHT
Displays all known peers and entries (both from `servers.txt` and DHT-discovered). You can add or remove entries here. The DHT status label shows how many entries were discovered at bootstrap.

### Search
Search for files across all connected P2P peers. Results show the filename, source peer, and type (`P2P` or `HTTP`). Double-clicking a result downloads the file.

### Blockchain
Displays the full local blockchain. Each row shows the block number, filename, file size, SHA-256 hash (truncated), sender identity, timestamp, and block hash. Only P2P transfers are recorded — HTTP downloads are excluded.

### Log
A timestamped, color-coded activity log showing all network events, errors, block mining, sync progress, and DHT activity.

---

## Protocol Commands (P2P)

The application uses a simple text-based TCP protocol:

| Command | Description |
|---|---|
| `LIST` | Request a list of files from a peer |
| `GET <filename>` | Download a file from a peer |
| `PUSH <filename> <size> <pubkey>` | Upload a file to a peer |
| `PUBKEY` | Request the peer's RSA public key |
| `NOTIFY_BLOCK <json>` | Broadcast a new blockchain block |
| `GET_CHAIN` | Request the full blockchain from a peer |
| `OK` / `ERROR` / `EXISTS` / `REJECTED` / `END` | Response tokens |

---

## Blockchain Details

- Each block records: file name, file size, SHA-256 hash, sender public key, receiver public key, sender signature, receiver signature, previous block hash, timestamp, nonce, and block hash.
- **Proof of Work** difficulty is set to 2 leading zeros (`POW_DIFF = 2`).
- Blocks are signed by both sender and receiver using `SHA256withRSA`.
- New blocks are broadcast to all known P2P peers after mining.
- On startup, the local chain is compared with peers and updated if a longer valid chain is found.

---

## DHT Bootstrap URLs

The following public URLs are contacted at startup to seed the peer list:

- `http://meento.atwebpages.com/servers.php`
- `https://meentos.netlify.app/servers.txt`
- `https://meento.neocities.org/servers.txt`
- `https://geocities.ws/meento/servers.txt`

Newly discovered P2P peers are merged into `servers.txt` automatically. HTTP file URLs are added to the runtime DHT set only.

---

## Supported HTTP File Extensions

Direct HTTP download is triggered for URLs ending in any of the following extensions:

`jpg`, `jpeg`, `png`, `gif`, `bmp`, `webp`, `svg`, `ico`, `mp4`, `mkv`, `avi`, `mov`, `wmv`, `flv`, `webm`, `m4v`, `mp3`, `aac`, `ogg`, `flac`, `wav`, `opus`, `m4a`, `pdf`, `doc`, `docx`, `xls`, `xlsx`, `ppt`, `pptx`, `odt`, `ods`, `zip`, `tar`, `gz`, `bz2`, `xz`, `rar`, `7z`, `cab`, `deb`, `rpm`, `exe`, `apk`, `dmg`, `iso`, `bin`, `img`, `msi`, `txt`, `csv`, `json`, `xml`, `html`, `htm`, `md`, `log`, `ini`, `cfg`, `conf`, `torrent`, `nfo`, `srt`, `ass`, `sub`

---

## Notes

- HTTP downloads do **not** create blockchain records and do **not** notify peers.
- Files are sanitized before saving to prevent path traversal.
- The application uses a thread pool (`CachedThreadPool`) for all network operations, keeping the UI responsive.
- The default P2P port is `52525`, configurable at runtime from the UI.
