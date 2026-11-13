import json
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def request_record(port, user_id, record_id):
    url = f"http://127.0.0.1:{port}/record?id={record_id}"
    request = Request(url, headers={"X-Lab-User": user_id})

    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)

tests = [
    ("Vulnerable: Alice reads Bob", 8000, "1001", "1002", True),
    ("Vulnerable: Bob reads Alice", 8000, "1002", "1001", True),
    ("Protected: Alice denied Bob", 8001, "1001", "1002", False),
    ("Protected: Bob denied Alice", 8001, "1002", "1001", False),
]

results = []

print("=" * 55)
print("AI RED TEAM CYBER RANGE - CROSS-USER ACCESS TEST")
print("=" * 55)

for name, port, user_id, record_id, expected_exposure in tests:
    status, data = request_record(port, user_id, record_id)
    exposed = status == 200 and "secret" in data
    passed = exposed == expected_exposure

    results.append({
        "test": name,
        "status": status,
        "exposure_detected": exposed,
        "passed": passed
    })

    print(f"\n{name}")
    print(f"HTTP STATUS: {status}")
    print(f"CROSS-USER EXPOSURE: {exposed}")
    print(f"TEST PASSED: {passed}")

Path("results").mkdir(exist_ok=True)
with open("results/cross_user_access.json", "w") as file:
    json.dump(results, file, indent=2)

print("\nSaved: results/cross_user_access.json")
