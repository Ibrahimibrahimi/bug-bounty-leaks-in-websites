"""
IP Reverse DNS Lookup Tool
- Generates IP wordlist from given names/ranges
- Randomly samples IPs and resolves hostnames
- Saves results to a text file
"""

import socket
import random
import ipaddress
import concurrent.futures
from pathlib import Path


# ──────────────────────────────────────────────
# 1.  Wordlist generator
# ──────────────────────────────────────────────

def generate_wordlist(names: list[str], output_file: str = "wordlist.txt") -> list[str]:
    """
    Generate an IP wordlist from a list of subnet names / CIDR blocks.

    `names` can be:
      - CIDR notation  : "192.168.1.0/24"
      - Plain IP       : "8.8.8.8"
      - Octet prefix   : "10.0"  -> expands to 10.0.0.0 - 10.0.255.255
    """
    ips: list[str] = []

    for name in names:
        name = name.strip()
        if not name:
            continue

        try:
            network = ipaddress.ip_network(name, strict=False)
            ips.extend(str(ip) for ip in network.hosts())
        except ValueError:
            parts = name.split(".")
            if 1 <= len(parts) <= 3 and all(p.isdigit() for p in parts):
                missing = 4 - len(parts)
                base = name + ".0" * missing
                try:
                    prefix_len = len(parts) * 8
                    network = ipaddress.ip_network(f"{base}/{prefix_len}", strict=False)
                    ips.extend(str(ip) for ip in network.hosts())
                except ValueError:
                    print(f"[!] Skipping unrecognised entry: {name}")
            else:
                print(f"[!] Skipping unrecognised entry: {name}")

    Path(output_file).write_text("\n".join(ips))
    print(f"[+] Wordlist saved: {output_file}  ({len(ips):,} IPs)")
    return ips


# ──────────────────────────────────────────────
# 2.  Reverse-DNS resolver
# ──────────────────────────────────────────────

def reverse_lookup(ip: str) -> tuple[str, str | None]:
    """Return (ip, hostname) or (ip, None) on failure."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return ip, hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip, None


def lookup_batch(
    wordlist: list[str],
    sample_size: int = 10_000,
    output_file: str = "results.txt",
    workers: int = 200,
) -> None:
    pool = random.sample(wordlist, min(sample_size, len(wordlist)))
    print(f"\n[+] Resolving {len(pool):,} IPs using {workers} threads ...\n")

    resolved: list[tuple[str, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(reverse_lookup, ip): ip for ip in pool}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            ip, hostname = future.result()
            done += 1
            if hostname:
                resolved.append((ip, hostname))
            if done % 1000 == 0:
                print(f"  ... {done:,}/{len(pool):,}  matched so far: {len(resolved):,}")

    lines = [f"{ip} --> {hostname}" for ip, hostname in sorted(resolved)]
    Path(output_file).write_text("\n".join(lines))
    print(f"\n[+] Done! {len(resolved):,} IPs with hostnames saved -> {output_file}")


# ──────────────────────────────────────────────
# 3.  Helpers
# ──────────────────────────────────────────────

def ask(msg: str, default: str = "") -> str:
    val = input(msg).strip()
    return val if val else default


def do_generate() -> list[str]:
    print("\n  Enter CIDRs or octet prefixes, one per line.")
    print("  Examples:  192.168.1.0/24   |   10.0   |   8.8.8.8")
    print("  Press Enter on an empty line when done.\n")
    names = []
    while True:
        entry = input("  > ").strip()
        if not entry:
            break
        names.append(entry)
    if not names:
        print("[!] No entries given, returning to menu.")
        return []
    out = ask("  Save wordlist as [wordlist.txt]: ", "wordlist.txt")
    return generate_wordlist(names, out)


def do_lookup(wordlist: list[str] | None = None) -> None:
    if wordlist is None:
        path = ask("  Wordlist file [wordlist.txt]: ", "wordlist.txt")
        if not Path(path).exists():
            print(f"[!] File not found: {path}")
            return
        lines = Path(path).read_text().splitlines()
        wordlist = [ip.strip() for ip in lines if ip.strip()]
        print(f"[+] Loaded {len(wordlist):,} IPs from {path}")

    sample_size = int(ask(f"  Sample size [10000]: ", "10000"))
    workers     = int(ask("  Threads     [200]:   ", "200"))
    out         = ask("  Save results as [results.txt]: ", "results.txt")

    lookup_batch(wordlist, sample_size, out, workers)


# ──────────────────────────────────────────────
# 4.  Main menu
# ──────────────────────────────────────────────

def main():
    print("\n" + "=" * 48)
    print("      IP Reverse DNS Lookup Tool")
    print("=" * 48)

    while True:
        print("\n  [1]  Generate wordlist")
        print("  [2]  Lookup IPs from existing wordlist")
        print("  [3]  Generate wordlist + run lookup")
        print("  [4]  Exit")

        choice = ask("\n  Choose: ")

        if choice == "1":
            do_generate()

        elif choice == "2":
            do_lookup()

        elif choice == "3":
            wordlist = do_generate()
            if wordlist:
                do_lookup(wordlist)

        elif choice == "4":
            print("\n[+] Bye!\n")
            break

        else:
            print("[!] Invalid choice, please enter 1-4.")


if __name__ == "__main__":
    main()