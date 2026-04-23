import socket
import random
import concurrent.futures

NUM_IPS = 50
MAX_WORKERS = 20
OUTPUT_FILE = "results_hosts.txt"


def random_ip() -> str:
    return ".".join(str(random.randint(0, 254)) for _ in range(4))


def reverse_lookup(ip: str) -> tuple[str, str | None]:
    """Return (ip, hostname) or (ip, None) on failure."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return ip, hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip, None


ips = [random_ip() for _ in range(NUM_IPS)]
found = []

with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {executor.submit(reverse_lookup, ip): ip for ip in ips}
    for future in concurrent.futures.as_completed(futures):
        ip, hostname = future.result()
        if hostname:
            print(f"[+] Found : {ip} => {hostname}")
            found.append(f"{ip} => {hostname}\n")
        else:
            print(f"[-] Not found for {ip}")

print(f"\nFound {len(found)} hostnames — saving to {OUTPUT_FILE} ...")
with open(OUTPUT_FILE, "w") as f:
    f.writelines(found)
