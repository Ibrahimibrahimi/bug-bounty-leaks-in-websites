#!/usr/bin/env python3
"""
======================================================
  WebSecretScanner - Authorized Security Recon Tool
======================================================
  Use ONLY on systems you own or have written permission
  to test. Unauthorized use is illegal and unethical.
======================================================
"""

import re
import sys
import json
import time
import hashlib
import argparse
import requests
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ──────────────────────────────────────────────
#  PATTERN DEFINITIONS
# ──────────────────────────────────────────────

PATTERNS = {
    # ── Cloud Providers ──
    "AWS Access Key":           (re.compile(r'AKIA[0-9A-Z]{16}'),                                   "CRITICAL"),
    "AWS Secret Key":           (re.compile(r'(?i)aws.{0,20}secret.{0,20}[\'"]([A-Za-z0-9/+=]{40})[\'"]'), "CRITICAL"),
    "AWS Session Token":        (re.compile(r'ASIA[0-9A-Z]{16}'),                                   "HIGH"),
    "GCP Service Account":      (re.compile(r'"type":\s*"service_account"'),                        "CRITICAL"),
    "Google API Key":           (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                             "HIGH"),
    "Firebase Config":          (re.compile(r'firebaseConfig\s*=\s*\{[^}]+apiKey[^}]+\}'),          "MEDIUM"),
    "Firebase DB URL":          (re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),                "INFO"),
    "Azure Storage Key":        (re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'), "CRITICAL"),
    "Azure Client Secret":      (re.compile(r'(?i)azure.{0,20}client.{0,20}secret.{0,20}[\'"]([^\s\'"]{30,})[\'"]'), "CRITICAL"),
    "Heroku API Key":           (re.compile(r'heroku[_\-\s]?api[_\-\s]?key\s*[:=]\s*[\'"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\'"]?', re.I), "HIGH"),

    # ── Payment ──
    "Stripe Live Key":          (re.compile(r'sk_live_[0-9a-zA-Z]{24}'),                            "CRITICAL"),
    "Stripe Restricted Key":    (re.compile(r'rk_live_[0-9a-zA-Z]{24}'),                            "HIGH"),
    "Stripe Publishable Key":   (re.compile(r'pk_live_[0-9a-zA-Z]{24}'),                            "MEDIUM"),
    "PayPal Token":             (re.compile(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'), "CRITICAL"),
    "Braintree Key":            (re.compile(r'(?i)braintree.{0,20}[\'"]([a-z0-9]{32})[\'"]'),       "HIGH"),

    # ── Communication ──
    "Slack Bot Token":          (re.compile(r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}'),     "HIGH"),
    "Slack User Token":         (re.compile(r'xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{30}'),     "HIGH"),
    "Slack Webhook":            (re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'), "HIGH"),
    "Twilio SID":               (re.compile(r'AC[a-z0-9]{32}'),                                     "HIGH"),
    "Twilio Auth Token":        (re.compile(r'(?i)twilio.{0,20}auth.{0,20}[\'"]([a-z0-9]{32})[\'"]'), "CRITICAL"),
    "SendGrid Key":             (re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'),         "HIGH"),
    "Mailchimp API Key":        (re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'),                          "HIGH"),
    "Mailgun API Key":          (re.compile(r'key-[0-9a-zA-Z]{32}'),                                "HIGH"),

    # ── Source Control / CI ──
    "GitHub Token (classic)":   (re.compile(r'ghp_[a-zA-Z0-9]{36}'),                               "CRITICAL"),
    "GitHub OAuth":             (re.compile(r'gho_[a-zA-Z0-9]{36}'),                                "CRITICAL"),
    "GitHub App Token":         (re.compile(r'ghs_[a-zA-Z0-9]{36}'),                                "CRITICAL"),
    "GitHub Fine-Grained":      (re.compile(r'github_pat_[a-zA-Z0-9_]{82}'),                        "CRITICAL"),
    "GitLab Token":             (re.compile(r'glpat-[a-zA-Z0-9\-_]{20}'),                           "CRITICAL"),
    "NPM Token":                (re.compile(r'npm_[a-zA-Z0-9]{36}'),                                "HIGH"),

    # ── Social / Auth ──
    "Facebook Access Token":    (re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),                         "HIGH"),
    "Twitter Bearer Token":     (re.compile(r'AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+'),                "HIGH"),
    "Twitter API Key":          (re.compile(r'(?i)twitter.{0,20}api.{0,20}[\'"]([a-zA-Z0-9]{25})[\'"]'), "HIGH"),
    "LinkedIn Token":           (re.compile(r'(?i)linkedin.{0,20}[\'"]([a-zA-Z0-9]{40,})[\'"]'),    "MEDIUM"),
    "Discord Token":            (re.compile(r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}'),            "HIGH"),
    "Discord Webhook":          (re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+'), "HIGH"),

    # ── Crypto / Keys ──
    "RSA Private Key":          (re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),                    "CRITICAL"),
    "EC Private Key":           (re.compile(r'-----BEGIN EC PRIVATE KEY-----'),                     "CRITICAL"),
    "OpenSSH Private Key":      (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),                "CRITICAL"),
    "PKCS8 Private Key":        (re.compile(r'-----BEGIN PRIVATE KEY-----'),                        "CRITICAL"),
    "PGP Private Key":          (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),              "CRITICAL"),

    # ── Tokens / JWTs ──
    "JWT Token":                (re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'), "MEDIUM"),
    "Bearer Token":             (re.compile(r'(?i)bearer\s+([a-zA-Z0-9\-_\.=]{20,})'),             "MEDIUM"),
    "Basic Auth in URL":        (re.compile(r'https?://[a-zA-Z0-9]+:[a-zA-Z0-9@%!$&\'()*+,;=\-._~:/?#[\]]+@'), "HIGH"),

    # ── Database ──
    "MongoDB URI":              (re.compile(r'mongodb(\+srv)?://[^\s\'"<>]+'),                      "CRITICAL"),
    "PostgreSQL URI":           (re.compile(r'postgres(?:ql)?://[^\s\'"<>]+'),                      "CRITICAL"),
    "MySQL URI":                (re.compile(r'mysql://[^\s\'"<>]+'),                                "CRITICAL"),
    "Redis URI":                (re.compile(r'redis://[^\s\'"<>]+'),                                "HIGH"),

    # ── Generic Secrets ──
    "Generic API Key":          (re.compile(r'(?i)api[_\-]?key\s*[:=]\s*[\'"]([^\s\'"<>]{16,})[\'"]'), "MEDIUM"),
    "Generic Secret":           (re.compile(r'(?i)secret[_\-]?key\s*[:=]\s*[\'"]([^\s\'"<>]{16,})[\'"]'), "MEDIUM"),
    "Generic Password":         (re.compile(r'(?i)password\s*[:=]\s*[\'"]([^\s\'"<>]{8,})[\'"]'),   "MEDIUM"),
    "Generic Token":            (re.compile(r'(?i)(?:auth|access)[_\-]?token\s*[:=]\s*[\'"]([^\s\'"<>]{20,})[\'"]'), "MEDIUM"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
SEVERITY_COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[93m",
                   "MEDIUM": "\033[94m", "INFO": "\033[96m", "RESET": "\033[0m"}

# ──────────────────────────────────────────────
#  FIREBASE SPECIFIC CHECKS
# ──────────────────────────────────────────────


def check_firebase_db(project_id: str, session: requests.Session) -> list:
    """Check if Firebase Realtime Database has open read rules."""
    findings = []
    endpoints = [
        f"https://{project_id}.firebaseio.com/.json",
        f"https://{project_id}-default-rtdb.firebaseio.com/.json",
    ]
    for url in endpoints:
        try:
            r = session.get(url, timeout=8)
            if r.status_code == 200:
                findings.append({
                    "type": "Firebase Open DB",
                    "severity": "CRITICAL",
                    "url": url,
                    "detail": f"Database publicly readable! Size: {len(r.text)} bytes",
                    "evidence": r.text[:200],
                })
            elif r.status_code == 401:
                findings.append({
                    "type": "Firebase DB (Auth Required)",
                    "severity": "INFO",
                    "url": url,
                    "detail": "DB exists but requires authentication",
                    "evidence": "",
                })
        except Exception:
            pass
    return findings


def check_firebase_storage(project_id: str, session: requests.Session) -> list:
    """Check if Firebase Storage bucket is publicly listable."""
    findings = []
    url = f"https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o"
    try:
        r = session.get(url, timeout=8)
        if r.status_code == 200:
            findings.append({
                "type": "Firebase Open Storage",
                "severity": "CRITICAL",
                "url": url,
                "detail": "Storage bucket is publicly listable!",
                "evidence": r.text[:300],
            })
        elif r.status_code == 403:
            findings.append({
                "type": "Firebase Storage (Protected)",
                "severity": "INFO",
                "url": url,
                "detail": "Storage exists but is protected",
                "evidence": "",
            })
    except Exception:
        pass
    return findings


def check_firestore(project_id: str, api_key: str, session: requests.Session) -> list:
    """Check if Firestore is publicly readable."""
    findings = []
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
    try:
        r = session.get(url, params={"key": api_key}, timeout=8)
        if r.status_code == 200:
            findings.append({
                "type": "Firestore Open Read",
                "severity": "CRITICAL",
                "url": url,
                "detail": "Firestore documents are publicly readable!",
                "evidence": r.text[:300],
            })
    except Exception:
        pass
    return findings


def extract_firebase_config(content: str) -> dict:
    """Extract Firebase config object from page source."""
    config = {}
    fields = ["apiKey", "authDomain", "databaseURL", "projectId",
              "storageBucket", "messagingSenderId", "appId"]
    for field in fields:
        m = re.search(
            rf'["\']?{field}["\']?\s*:\s*["\']([^"\']+)["\']', content)
        if m:
            config[field] = m.group(1)
    return config


# ──────────────────────────────────────────────
#  JS SOURCE MAP DISCOVERY
# ──────────────────────────────────────────────

def find_js_sourcemaps(url: str, content: str, session: requests.Session) -> list:
    """Find and fetch JS source maps which often contain full source code."""
    findings = []
    # Look for sourceMappingURL comments
    sm_pattern = re.compile(r'//# sourceMappingURL=(.+\.map)')
    for match in sm_pattern.finditer(content):
        map_file = match.group(1)
        map_url = urljoin(url, map_file) if not map_file.startswith(
            "http") else map_file
        try:
            r = session.get(map_url, timeout=8)
            if r.status_code == 200:
                findings.append({
                    "type": "JS Source Map Exposed",
                    "severity": "HIGH",
                    "url": map_url,
                    "detail": f"Source map accessible ({len(r.text)} bytes) — may contain full source",
                    "evidence": "",
                })
        except Exception:
            pass
    return findings


# ──────────────────────────────────────────────
#  ROBOTS / SITEMAP / COMMON PATHS
# ──────────────────────────────────────────────

INTERESTING_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.js", "/config.json", "/settings.json", "/app.config.js",
    "/firebase.json", "/.firebaserc", "/firestore.rules", "/storage.rules",
    "/google-services.json", "/GoogleService-Info.plist",
    "/api/config", "/api/keys", "/api/settings",
    "/.git/config", "/.git/HEAD",
    "/wp-config.php", "/wp-config.php.bak",
    "/backup.sql", "/database.sql", "/dump.sql",
    "/admin/config", "/dashboard/config",
]


def probe_common_paths(base_url: str, session: requests.Session) -> list:
    """Probe common sensitive file paths."""
    findings = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    def check_path(path):
        url = base + path
        try:
            r = session.get(url, timeout=6, allow_redirects=False)
            if r.status_code in (200, 301, 302) and len(r.text) > 10:
                return {
                    "type": "Sensitive Path Exposed",
                    "severity": "HIGH",
                    "url": url,
                    "detail": f"HTTP {r.status_code} — {len(r.text)} bytes",
                    "evidence": r.text[:150],
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(check_path, INTERESTING_PATHS):
            if result:
                findings.append(result)
    return findings


# ──────────────────────────────────────────────
#  MAIN SCANNER CLASS
# ──────────────────────────────────────────────

class SecretScanner:
    def __init__(self, urls: list, threads: int = 20, output: str = "scan_results",
                 deep: bool = False, firebase_check: bool = True):
        self.urls = urls
        self.threads = threads
        self.output = output
        self.deep = deep
        self.firebase_check = firebase_check
        self.findings = []
        self.seen_hashes = set()
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        })
        self.stats = defaultdict(int)

    def _dedup_finding(self, finding: dict) -> bool:
        """Return True if finding is new (not a duplicate)."""
        key = hashlib.md5(
            f"{finding.get('type')}{finding.get('evidence','')[:60]}".encode()
        ).hexdigest()
        with self._lock:
            if key in self.seen_hashes:
                return False
            self.seen_hashes.add(key)
            return True

    def _add_finding(self, finding: dict):
        if self._dedup_finding(finding):
            with self._lock:
                self.findings.append(finding)
                self.stats[finding["severity"]] += 1

    def scan_content(self, content: str, url: str):
        """Run all regex patterns against content."""
        for name, (pattern, severity) in PATTERNS.items():
            for match in pattern.finditer(content):
                self._add_finding({
                    "type": name,
                    "severity": severity,
                    "url": url,
                    "detail": f"Pattern matched in page source",
                    "evidence": match.group(0)[:120],
                })

    def scan_url(self, url: str):
        """Fetch a URL and run all checks on it."""
        self._cprint(f"  Scanning: {url}", "cyan")
        try:
            r = self.session.get(url, timeout=12)
            content = r.text
        except Exception as e:
            self._cprint(f"  Error fetching {url}: {e}", "red")
            return

        if r.status_code != 200:
            self._cprint(f"  HTTP {r.status_code} for {url}", "yellow")
            return

        # Secret pattern scan
        self.scan_content(content, url)

        # Source map discovery
        for f in find_js_sourcemaps(url, content, self.session):
            self._add_finding({**f, "url": url})

        # Firebase-specific checks
        if self.firebase_check:
            config = extract_firebase_config(content)
            if config:
                self._cprint(f"  Firebase config found at {url}", "yellow")
                project_id = config.get("projectId", "")
                api_key = config.get("apiKey", "")
                self._add_finding({
                    "type": "Firebase Config Detected",
                    "severity": "INFO",
                    "url": url,
                    "detail": f"Project: {project_id}",
                    "evidence": json.dumps(config),
                })
                if project_id:
                    for f in check_firebase_db(project_id, self.session):
                        self._add_finding(f)
                    for f in check_firebase_storage(project_id, self.session):
                        self._add_finding(f)
                    if api_key:
                        for f in check_firestore(project_id, api_key, self.session):
                            self._add_finding(f)

        # Deep mode: also probe common sensitive paths
        if self.deep:
            for f in probe_common_paths(url, self.session):
                self._add_finding(f)

        # Scan linked JS files
        if self.deep:
            js_pattern = re.compile(
                r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']')
            js_urls = [urljoin(url, m.group(1))
                       for m in js_pattern.finditer(content)]
            js_urls = [u for u in js_urls if urlparse(
                u).netloc == urlparse(url).netloc][:10]
            for js_url in js_urls:
                try:
                    jr = self.session.get(js_url, timeout=8)
                    if jr.status_code == 200:
                        self.scan_content(jr.text, js_url)
                        for f in find_js_sourcemaps(js_url, jr.text, self.session):
                            self._add_finding(f)
                except Exception:
                    pass

    def run(self):
        print(self._banner())
        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.scan_url, url): url for url in self.urls}
            for future in as_completed(futures):
                future.result()

        elapsed = time.time() - start
        self._print_summary(elapsed)
        self._save_results()

    # ── Output helpers ──────────────────────────────

    def _cprint(self, msg, color="reset"):
        colors = {"cyan": "\033[96m", "yellow": "\033[93m", "red": "\033[91m",
                  "green": "\033[92m", "reset": "\033[0m"}
        print(f"{colors.get(color,'')}{msg}\033[0m")

    def _banner(self):
        return """
\033[94m╔══════════════════════════════════════════════════════╗
║        WebSecretScanner — Authorized Use Only        ║
║  Scan for leaked API keys, tokens & misconfigs       ║
╚══════════════════════════════════════════════════════╝\033[0m"""

    def _print_summary(self, elapsed: float):
        print(f"\n\033[92m{'─'*54}")
        print(
            f"  Scan complete in {elapsed:.1f}s | {len(self.urls)} URLs | {len(self.findings)} findings")
        print(f"{'─'*54}\033[0m")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
            count = self.stats[sev]
            if count:
                color = SEVERITY_COLORS[sev]
                print(f"  {color}{sev:8s}\033[0m  {count} finding(s)")

        print(f"\n\033[1mFindings:\033[0m")
        sorted_findings = sorted(
            self.findings,
            key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)
        )
        for f in sorted_findings:
            color = SEVERITY_COLORS.get(f["severity"], "")
            print(f"  {color}[{f['severity']:8s}]\033[0m {f['type']}")
            print(f"           URL     : {f['url']}")
            print(f"           Detail  : {f['detail']}")
            if f.get("evidence"):
                print(f"           Evidence: {f['evidence'][:80]}...")
            print()

    def _save_results(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # ── TXT report ──
        txt_path = f"{self.output}_{ts}.txt"
        with open(txt_path, "w") as fh:
            fh.write("WebSecretScanner Report\n")
            fh.write(f"Generated: {datetime.now().isoformat()}\n")
            fh.write(f"URLs scanned: {len(self.urls)}\n\n")
            for f in sorted(self.findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
                fh.write(f"[{f['severity']}] {f['type']}\n")
                fh.write(f"  URL     : {f['url']}\n")
                fh.write(f"  Detail  : {f['detail']}\n")
                if f.get("evidence"):
                    fh.write(f"  Evidence: {f['evidence'][:200]}\n")
                fh.write("\n")

        # ── JSON report ──
        json_path = f"{self.output}_{ts}.json"
        with open(json_path, "w") as fh:
            json.dump({
                "meta": {
                    "generated": datetime.now().isoformat(),
                    "urls_scanned": len(self.urls),
                    "total_findings": len(self.findings),
                    "stats": dict(self.stats),
                },
                "findings": self.findings,
            }, fh, indent=2)

        print(f"\033[92m  Reports saved:\033[0m")
        print(f"    {txt_path}")
        print(f"    {json_path}")


# ──────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WebSecretScanner — Authorized security recon tool",
        epilog="Example: python secret_scanner.py -u https://myapp.com --deep --firebase"
    )
    parser.add_argument("-u", "--urls",    nargs="+", help="Target URLs")
    parser.add_argument("-f", "--file",    help="File with one URL per line")
    parser.add_argument("-t", "--threads", type=int,
                        default=20, help="Thread count (default 20)")
    parser.add_argument(
        "-o", "--output",  default="scan_results", help="Output filename prefix")
    parser.add_argument("--deep",          action="store_true",
                        help="Deep scan: crawl JS files + probe common paths")
    parser.add_argument("--no-firebase",   action="store_true",
                        help="Skip Firebase-specific checks")

    args = parser.parse_args()

    urls = []
    if args.urls:
        urls.extend(args.urls)
    if args.file:
        with open(args.file) as fh:
            urls.extend(line.strip() for line in fh if line.strip())

    if not urls:
        # Demo mode
        print("\033[93mNo URLs provided — running demo mode\033[0m")
        print(
            "Usage: python secret_scanner.py -u https://target.com [--deep] [--no-firebase]")
        print("       python secret_scanner.py -f urls.txt --threads 30 --deep")
        sys.exit(0)

    scanner = SecretScanner(
        urls=urls,
        threads=args.threads,
        output=args.output,
        deep=args.deep,
        firebase_check=not args.no_firebase,
    )
    scanner.run()


if __name__ == "__main__":
    main()
