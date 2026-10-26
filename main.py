
import subprocess
import sys
import time
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def start_process(script_name):
    script_path = BASE_DIR / script_name

    if not script_path.is_file():
        raise FileNotFoundError(
            f"Required file not found: {script_path}"
        )

    return subprocess.Popen(
        [sys.executable, str(script_path)],
        cwd=str(BASE_DIR),
    )


def stop_process(process, name):
    if process is None or process.poll() is not None:
        return

    print(f"[*] Stopping {name}...")
    process.terminate()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        print(f"[!] {name} did not stop. Forcing shutdown...")
        process.kill()
        process.wait()


def main():
    print("=" * 60)
    print("   Starting python_SIEM_SOAR SIEM & SOAR System")
    print("=" * 60)

    generator_process = None
    siem_process = None

    try:
        print("[*] Starting background Log Generator...")
        generator_process = start_process("log_generator.py")

        time.sleep(1.5)

        print("[*] Starting SIEM Detection Engine...")
        siem_process = start_process("siem_engine.py")

        time.sleep(1.0)

        print("[*] Launching Desktop Dashboard...")
        subprocess.run(
            [sys.executable, str(BASE_DIR / "dashboard.py")],
            cwd=str(BASE_DIR),
            check=False,
        )

    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")

    except (OSError, subprocess.SubprocessError) as error:
        print(f"[!] Process error: {error}")

    finally:
        print("\n[!] Shutting down SIEM/SOAR processes...")

        stop_process(siem_process, "SIEM Engine")
        stop_process(generator_process, "Log Generator")

        print("[-] System stopped. Goodbye!")


if __name__ == "__main__":
    main()
