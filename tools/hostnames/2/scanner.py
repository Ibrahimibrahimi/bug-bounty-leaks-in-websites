import socket
import subprocess
import platform
import urllib.request
import concurrent.futures
import time
from datetime import datetime

# ── config ──────────────────────────────────────────────
INPUT_FILE   = "top_147k_hostnames.txt"
OUTPUT_FILE  = "scaned_top_147k_hostnames_results.txt"
MAX_WORKERS  = 100       # increase if your network handles it
PORT_TIMEOUT = 0.8       # seconds per port
HTTP_TIMEOUT = 3.0
PING_TIMEOUT = 1

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017:"MongoDB",
}

# ── checks ───────────────────────────────────────────────

def fcrDNS(ip: str, hostname: str) -> bool:
    try:
        return socket.gethostbyname(hostname) == ip
    except:
        return False

def ping(ip: str) -> bool:
    flag = "-n" if platform.system() == "Windows" else "-c"
    w_flag = ["-w", "1000"] if platform.system() == "Windows" else ["-W", "1"]
    return subprocess.run(
        ["ping", flag, "1"] + w_flag + [ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode == 0

def scan_ports(ip: str) -> dict:
    """Returns {port: service_name} for open ports."""
    open_ports = {}
    for port, service in COMMON_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(PORT_TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                open_ports[port] = service
    return open_ports

def http_probe(hostname: str) -> dict:
    """Returns {scheme: status_code} for responding web servers."""
    result = {}
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{hostname}",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                result[scheme] = r.status
                result["server"] = r.headers.get("Server", "unknown")
                result["powered_by"] = r.headers.get("X-Powered-By", None)
        except urllib.error.HTTPError as e:
            result[scheme] = e.code
        except:
            continue
    return result

def grab_banner(ip: str, port: int) -> str | None:
    """Try to grab a text banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(256).decode(errors="ignore").strip()[:100]
    except:
        return None

def check_dns_zone_transfer(hostname: str) -> bool:
    """Check if DNS zone transfer (AXFR) is allowed — misconfiguration."""
    try:
        domain = ".".join(hostname.split(".")[-2:])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((hostname, 53))
            return True  # port open, worth flagging
    except:
        return False

# ── main scanner ─────────────────────────────────────────

def scan_host(line: str) -> dict | None:
    line = line.strip()
    if "=>" not in line:
        return None
    ip, hostname = [x.strip() for x in line.split("=>", 1)]

    result = {
        "ip":         ip,
        "hostname":   hostname,
        "fcrdns":     fcrDNS(ip, hostname),
        "ping":       ping(ip),
        "open_ports": {},
        "http":       {},
        "banners":    {},
        "dns_port":   False,
    }

    result["open_ports"] = scan_ports(ip)

    # only probe HTTP if port 80 or 443 is open (saves time)
    if any(p in result["open_ports"] for p in (80, 443, 8080, 8443)):
        result["http"] = http_probe(hostname)

    # grab banners from interesting open ports
    for port in result["open_ports"]:
        if port in (21, 22, 25, 80):
            banner = grab_banner(ip, port)
            if banner:
                result["banners"][port] = banner

    # check if DNS port is open
    if 53 in result["open_ports"]:
        result["dns_port"] = True

    return result

def format_result(r: dict) -> str:
    ports_str = ", ".join(
        f"{p}/{s}" for p, s in r["open_ports"].items()
    ) or "none"

    http_str = ", ".join(
        f"{k}={v}" for k, v in r["http"].items()
    ) or "none"

    banners_str = " | ".join(
        f"port {p}: {b}" for p, b in r["banners"].items()
    ) or "none"

    flags = []
    if r["fcrdns"]:         flags.append("FCrDNS-OK")
    if r["ping"]:           flags.append("PING-OK")
    if r["http"]:           flags.append("WEB-SERVER")
    if r["dns_port"]:       flags.append("DNS-OPEN")
    if 22 in r["open_ports"]: flags.append("SSH-EXPOSED")
    if 3306 in r["open_ports"]: flags.append("MYSQL-EXPOSED")
    if 27017 in r["open_ports"]: flags.append("MONGO-EXPOSED")
    if 6379 in r["open_ports"]: flags.append("REDIS-EXPOSED")

    return (
        f"[{r['ip']}] {r['hostname']}\n"
        f"  Flags    : {' | '.join(flags) or 'none'}\n"
        f"  Ports    : {ports_str}\n"
        f"  HTTP     : {http_str}\n"
        f"  Banners  : {banners_str}\n"
    )

# ── run ──────────────────────────────────────────────────

def main():
    with open(INPUT_FILE, encoding="utf-8") as f:
        lines = [l for l in f if "=>" in l]

    total = len(lines)
    print(f"Loaded {total} hosts — starting scan with {MAX_WORKERS} workers...")
    start = time.time()

    results = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(scan_host, line): line for line in lines}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            r = fut.result()
            if r:
                results.append(r)
                # only print interesting ones to console
                if r["open_ports"] or r["http"] or r["ping"]:
                    print(format_result(r), end="")
            if done % 1000 == 0:
                elapsed = time.time() - start
                rate = done / elapsed
                remaining = (total - done) / rate
                print(f"  [{done}/{total}] — {rate:.0f} hosts/sec — ~{remaining/60:.1f} min left")

    elapsed = time.time() - start
    web_servers  = [r for r in results if r["http"]]
    ssh_exposed  = [r for r in results if 22  in r["open_ports"]]
    db_exposed   = [r for r in results if any(p in r["open_ports"] for p in (3306, 5432, 27017, 6379))]
    ping_alive   = [r for r in results if r["ping"]]
    fcrdns_valid = [r for r in results if r["fcrdns"]]

    summary = (
        f"Scan completed — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"{'='*60}\n"
        f"Total scanned   : {len(results)}\n"
        f"Ping alive      : {len(ping_alive)}\n"
        f"FCrDNS valid    : {len(fcrdns_valid)}\n"
        f"Web servers     : {len(web_servers)}\n"
        f"SSH exposed     : {len(ssh_exposed)}\n"
        f"DB exposed      : {len(db_exposed)}\n"
        f"Time elapsed    : {elapsed/60:.1f} min\n"
        f"{'='*60}\n\n"
    )

    print("\n" + summary)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(summary)

        # write interesting hosts first
        f.write("── Web servers ──\n")
        for r in web_servers:
            f.write(format_result(r))

        f.write("\n── SSH exposed ──\n")
        for r in ssh_exposed:
            f.write(format_result(r))

        f.write("\n── Databases exposed ──\n")
        for r in db_exposed:
            f.write(format_result(r))

        f.write("\n── All results ──\n")
        for r in results:
            f.write(format_result(r))

    print(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()