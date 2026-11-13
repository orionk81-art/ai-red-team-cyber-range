import json
from pathlib import Path
from urllib.request import urlopen

BASE_URL = "http://127.0.0.1:8000"

def fetch_record(record_id):
    url = f"{BASE_URL}/record?id={record_id}"
    with urlopen(url, timeout=5) as response:
        return response.status, json.load(response)

print("=" * 55)
print("AI RED TEAM CYBER RANGE")
print("AUTOMATED ACCESS CONTROL SECURITY TEST")
print("=" * 55)

try:
    alice_status, alice = fetch_record("1001")
    bob_status, bob = fetch_record("1002")

    print(f"\nAlice: HTTP {alice_status}")
    print(f"Bob: HTTP {bob_status}")

    vulnerable = (
        alice_status == 200
        and bob_status == 200
        and alice.get("secret") == "LAB-ALICE-001"
        and bob.get("secret") == "LAB-BOB-002"
    )

    if vulnerable:
        print("\n[DETECTED] Unauthenticated private record exposure")
        print("Both private records are accessible without login.")
    else:
        print("\n[NOT DETECTED] Expected exposure not observed")

    result = {
        "test": "unauthenticated_private_record_exposure",
        "vulnerability_detected": vulnerable,
        "alice_http_status": alice_status,
        "bob_http_status": bob_status
    }

    Path("results").mkdir(exist_ok=True)

    with open("results/access_control_test.json", "w") as file:
        json.dump(result, file, indent=2)

    print("\nResults saved: results/access_control_test.json")

except Exception as error:
    print(f"\n[ERROR] {error}")
