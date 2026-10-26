
import ipaddress
import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soar_actions import block_ip_address, get_blocked_ips


BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "security.log"

LOG_PATTERN = re.compile(
    r"^\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)$"
)

IP_PATTERN = re.compile(r"from IP ([\d.]+)")

FAILED_LOGIN_THRESHOLD = 4
DETECTION_WINDOW = timedelta(minutes=5)
POLL_INTERVAL = 5


def parse_log_line(line):
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    timestamp_text, level, event_type, message = match.groups()

    try:
        timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "level": level,
        "event_type": event_type,
        "message": message,
    }


def extract_ip(message):
    match = IP_PATTERN.search(message)

    if not match:
        return None

    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


def main():
    print("[*] SIEM Detection Engine started.")
    print(
        f"[*] Detection rule: {FAILED_LOGIN_THRESHOLD} failed SSH "
        f"logins within {int(DETECTION_WINDOW.total_seconds() // 60)} minutes."
    )

    failed_attempts = deque()
    alerted_ips = set()
    blocked_ips = get_blocked_ips()
    last_position = 0

    try:
        while True:
            if not LOG_FILE.exists():
                time.sleep(POLL_INTERVAL)
                continue

            try:
                if LOG_FILE.stat().st_size < last_position:
                    # The log file was truncated or recreated.
                    last_position = 0
                    failed_attempts.clear()
                    alerted_ips.clear()

                with LOG_FILE.open("r", encoding="utf-8") as log_file:
                    log_file.seek(last_position)
                    new_lines = log_file.readlines()
                    last_position = log_file.tell()

            except OSError as error:
                print(f"[!] Could not read security log: {error}")
                time.sleep(POLL_INTERVAL)
                continue

            for line in new_lines:
                event = parse_log_line(line)

                if event is None:
                    continue

                if event["event_type"] != "SSH_LOGIN_FAILED":
                    continue

                ip = extract_ip(event["message"])

                if ip is None:
                    continue

                now = datetime.now(timezone.utc)

                while (
                    failed_attempts
                    and now - failed_attempts[0][0] > DETECTION_WINDOW
                ):
                    failed_attempts.popleft()

                event_time = event["timestamp"]

                # Ignore old events and timestamps far in the future.
                if (
                    event_time < now - DETECTION_WINDOW
                    or event_time > now + timedelta(seconds=30)
                ):
                    continue

                failed_attempts.append((event_time, ip))

                ip_attempt_count = sum(
                    1
                    for _, failed_ip in failed_attempts
                    if failed_ip == ip
                )

                if ip_attempt_count < FAILED_LOGIN_THRESHOLD:
                    continue

                if ip in alerted_ips:
                    continue

                if ip in blocked_ips:
                    alerted_ips.add(ip)
                    continue

                reason = (
                    f"Brute-force simulation detected: "
                    f"{ip_attempt_count} failed SSH logins "
                    f"within {DETECTION_WINDOW.total_seconds() / 60:g} minutes."
                )

                print(f"[ALERT] {reason} Source IP: {ip}")

                block_ip_address(ip, reason)

                # Avoid repeating the same response during this run.
                alerted_ips.add(ip)
                blocked_ips.add(ip)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n[-] SIEM Detection Engine stopped.")


if __name__ == "__main__":
    main()
