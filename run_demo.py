
import subprocess
import sys
import time
import socket
from pathlib import Path

# AI Red Team Cyber Range
# Automated local demonstration launcher

HOST = "127.0.0.1"

SERVERS = [
    ("Vulnerable Application", "vulnerable_app.py", 8000),
    ("Protected Application", "secure_app.py", 8001),
]

TESTS = [
    ("Security Comparison", "security_comparison.py"),
    ("Agent Benchmark", "agent_benchmark.py"),
]

BASE_DIR = Path(__file__).resolve().parent


def port_is_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((HOST, port)) == 0


def wait_for_server(process, port, timeout=10):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"Server process exited before port {port} became ready."
            )

        if port_is_open(port):
            return

        time.sleep(0.2)

    raise TimeoutError(f"Server on port {port} did not start.")


def run_test(name, filename):
    print(f"\n{'=' * 60}")
    print(f"RUNNING: {name}")
    print("=" * 60)

    result = subprocess.run(
        [sys.executable, str(BASE_DIR / filename)],
        cwd=BASE_DIR,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{name} failed with exit code {result.returncode}."
        )

    print(f"\nCOMPLETED: {name}")


def main():
    processes = []

    print("=" * 60)
    print("AI RED TEAM CYBER RANGE - AUTOMATED DEMONSTRATION")
    print("=" * 60)

    try:
        # Avoid interfering with servers already running.
        for name, filename, port in SERVERS:
            if port_is_open(port):
                raise RuntimeError(
                    f"Port {port} is already occupied. "
                    "Stop the existing server before running this demo."
                )

        # Start the two local lab applications.
        for name, filename, port in SERVERS:
            print(f"\nStarting {name} on {HOST}:{port}...")

            process = subprocess.Popen(
                [sys.executable, str(BASE_DIR / filename)],
                cwd=BASE_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            processes.append(process)
            wait_for_server(process, port)

            print(f"READY: {name}")

        # Run the existing test scripts.
        for name, filename in TESTS:
            run_test(name, filename)

        print("\n" + "=" * 60)
        print("DEMONSTRATION COMPLETED")
        print("=" * 60)
        print("Security comparison: results/security_comparison.json")
        print("Review the agent benchmark output above.")
        print("Both local applications will now shut down.")

    except Exception as error:
        print(f"\nERROR: {error}")
        return 1

    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()

                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        print("\nLocal lab processes stopped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
