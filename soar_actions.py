
import ipaddress
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"

BLOCKED_IP_FILE = LOG_DIR / "blocked_ips.txt"
SOAR_LOG_FILE = LOG_DIR / "soar_actions.log"


def ensure_log_dirs():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_blocked_ips():
    ensure_log_dirs()

    if not BLOCKED_IP_FILE.exists():
        return set()

    blocked_ips = set()

    with BLOCKED_IP_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            value = line.strip()

            if not value:
                continue

            try:
                blocked_ips.add(str(ipaddress.ip_address(value)))
            except ValueError:
                continue

    return blocked_ips


def block_ip_address(
    ip_address,
    reason="Suspicious activity / Brute-force",
):
    ensure_log_dirs()

    try:
        ip_address = str(ipaddress.ip_address(ip_address.strip()))
    except (ValueError, AttributeError):
        print(f"[!] Invalid IP address: {ip_address!r}")
        return False

    blocked_ips = get_blocked_ips()

    if ip_address in blocked_ips:
        print(f"[SOAR] IP {ip_address} is already recorded.")
        return False

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with BLOCKED_IP_FILE.open("a", encoding="utf-8") as file:
        file.write(f"{ip_address}\n")

    action_log = (
        f"[{timestamp}] [SIMULATED_ACTION] "
        f"Recorded IP: {ip_address} | Reason: {reason}\n"
    )

    with SOAR_LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(action_log)

    print(
        f"[SOAR SIMULATION] IP {ip_address} recorded. "
        f"Reason: {reason}"
    )

    return True


if __name__ == "__main__":
    print("[*] SOAR simulation module loaded.")
    print("[*] No real firewall rules will be changed.")
