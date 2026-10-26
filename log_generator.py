
import random
import time
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "security.log"

IP_ADDRESSES = [
    "192.168.1.50",
    "10.0.0.15",
    "203.0.113.42",
    "198.51.100.23",
    "192.168.1.105",
    "203.0.113.75",
]

USERS = ["root", "admin", "john", "ubuntu", "guest", "postgres"]

EVENT_TYPES = [
    "SSH_LOGIN_SUCCESS",
    "SSH_LOGIN_FAILED",
    "PORT_SCAN_DETECTED",
    "FIREWALL_BLOCK",
]


def generate_log_entry():
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    ip = random.choice(IP_ADDRESSES)
    user = random.choice(USERS)

    event_type = random.choices(
        EVENT_TYPES,
        weights=[25, 45, 20, 10],
        k=1,
    )[0]

    if event_type == "SSH_LOGIN_SUCCESS":
        level = "INFO"
        message = (
            f"Successful SSH login for user '{user}' from IP {ip}"
        )

    elif event_type == "SSH_LOGIN_FAILED":
        level = "WARNING"
        message = (
            f"Failed SSH login attempt for user '{user}' from IP {ip}"
        )

    elif event_type == "PORT_SCAN_DETECTED":
        level = "ERROR"
        message = (
            f"Potential port scan detected originating from IP {ip}"
        )

    else:
        level = "INFO"
        message = (
            f"Firewall blocked incoming connection from IP {ip}"
        )

    return f"[{timestamp}] [{level}] [{event_type}] {message}\n"


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print(
        f"[+] Log Generator started. Writing logs to '{LOG_FILE}'\n"
        "[+] Press Ctrl+C to stop."
    )

    try:
        while True:
            log_entry = generate_log_entry()

            with LOG_FILE.open("a", encoding="utf-8") as log_file:
                log_file.write(log_entry)

            print(f"Generated -> {log_entry.strip()}")

            time.sleep(random.uniform(1.0, 3.0))

    except KeyboardInterrupt:
        print("\n[-] Log Generator stopped by user.")


if __name__ == "__main__":
    main()
