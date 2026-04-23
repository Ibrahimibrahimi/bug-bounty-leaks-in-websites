import socket
import concurrent.futures
import random 

def reverse_lookup(ip: str) -> tuple[str, str | None]:
    """Return (ip, hostname) or (ip, None) on failure."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return ip, hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip, None

def generate_ips():
    r = random.choice
    return f""

def main():
    found = []
    ip_generator = generate_ips()

    # Using ThreadPoolExecutor for I/O bound tasks like DNS lookups
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all tasks
        futures = [executor.submit(reverse_lookup, ip) for ip in ip_generator]

        for future in concurrent.futures.as_completed(futures):
            ip, hostname = future.result()
            if hostname is not None:
                print("Found : ", ip, "=> ", hostname)
                found.append(f"{hostname}\n")
            else:
                # Optional: comment out for less console output
                # print("Not found for ", ip)
                pass

    print(f"Found : {len(found)} hostnames, saving to results_hosts.txt ...")
    with open("results_hosts.txt", "w") as file:
        file.writelines(found)

if __name__ == "__main__":
    main()