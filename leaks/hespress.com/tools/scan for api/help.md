# WebSecretScanner

A Python tool for scanning web applications for leaked API keys, tokens, and security misconfigurations. **For authorized security testing only.**

---

## Features

- **50+ secret patterns** — AWS, Google, Firebase, Stripe, GitHub, Slack, Discord, JWT, private keys, database URIs, and more
- **Firebase deep checks** — extracts `firebaseConfig` from page source and actively tests if the Realtime Database, Firestore, and Storage bucket have open/public rules
- **JS source map detection** — finds exposed `.map` files that may contain full original source code
- **Sensitive path probing** — checks for exposed `.env`, `firebase.json`, `.git/config`, `wp-config.php`, SQL dumps, and 20+ other common paths (with `--deep`)
- **JS file crawler** — follows same-domain `<script>` tags and scans linked JS files (with `--deep`)
- **Severity levels** — findings are rated CRITICAL / HIGH / MEDIUM / INFO
- **Deduplication** — identical findings across multiple files are merged automatically
- **Dual output** — saves a `.txt` report and a `.json` report with timestamps

---

## Installation

```bash
pip install requests
```

---

## Usage

```bash
# Scan a single URL
python secret_scanner.py -u https://example.com

# Deep scan (crawl JS files + probe sensitive paths)
python secret_scanner.py -u https://example.com --deep

# Scan multiple URLs from a file
python secret_scanner.py -f urls.txt --threads 30

# Skip Firebase-specific checks
python secret_scanner.py -u https://example.com --no-firebase
```

---

## Options

| Flag | Description |
|------|-------------|
| `-u URL [URL ...]` | One or more target URLs |
| `-f FILE` | Text file with one URL per line |
| `-t, --threads` | Number of parallel threads (default: 20) |
| `-o, --output` | Output filename prefix (default: `scan_results`) |
| `--deep` | Enable JS crawling and path probing |
| `--no-firebase` | Skip Firebase-specific checks |
