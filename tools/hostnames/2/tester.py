import socket
import subprocess
import platform
import urllib.request
import concurrent.futures

COMMON_PORTS = [22, 25, 80, 443, 8080, 3306]
OUTPUT_FILE = "test_results.txt"


def fcrDNS(ip, hostname):
    try:
        return socket.gethostbyname(hostname) == ip
    except:
        return False


def ping(ip):
    flag = "-n" if platform.system() == "Windows" else "-c"
    return subprocess.run(["ping", flag, "1", ip],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def scan_ports(ip, timeout=1.0):
    open_ports = []
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports


def http_probe(hostname, timeout=3.0):
    for scheme in ("https", "http"):
        try:
            with urllib.request.urlopen(f"{scheme}://{hostname}", timeout=timeout) as r:
                return f"{scheme.upper()} {r.status}"
        except:
            continue
    return None


def test_host(ip: str, hostname: str) -> dict:
    return {
        "ip": ip,
        "hostname": hostname,
        "fcrdns": fcrDNS(ip, hostname),
        "ping": ping(ip),
        "open_ports": scan_ports(ip),
        "http": http_probe(hostname),
    }


def format_result(r: dict) -> str:
    lines = [
        f"[{r['ip']}] {r['hostname']}",
        f"  FCrDNS  : {'✓' if r['fcrdns'] else '✗'}",
        f"  Ping    : {'✓' if r['ping'] else '✗'}",
        f"  Ports   : {r['open_ports'] or 'none'}",
        f"  HTTP    : {r['http'] or 'none'}",
        ""  # blank line between entries
    ]
    return "\n".join(lines)


# --- Load results_hosts.txt ---
hosts = []
with open("hostnames/2/top_14l_hostnames.txt") as f:
    for line in f:
        line = line.strip()
        if "=>" in line:
            ip, hostname = [x.strip() for x in line.split("=>")]
            hosts.append((ip, hostname))

# --- Test all hosts concurrently ---
results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(test_host, ip, hn) for ip, hn in hosts]
    for fut in concurrent.futures.as_completed(futures):
        r = fut.result()
        results.append(r)
        print(format_result(r))

# --- Save to file ---
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(f"Host Test Results — {len(results)} hosts tested\n")
    f.write("=" * 50 + "\n\n")
    for r in results:
        f.write(format_result(r))

print(f"Results saved to {OUTPUT_FILE}")