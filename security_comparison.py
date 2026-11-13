import json
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def test_request(port, record_id, user=None):
    url = f"http://127.0.0.1:{port}/record?id={record_id}"
    headers = {"X-Lab-User": user} if user else {}
    request = Request(url, headers=headers)

    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)

tests = [
    ("Vulnerable: anonymous reads Alice", 8000, "1001", None, 200),
    ("Vulnerable: anonymous reads Bob", 8000, "1002", None, 200),
    ("Protected: anonymous blocked", 8001, "1001", None, 401),
    ("Protected: Alice reads Alice", 8001, "1001", "1001", 200),
    ("Protected: Alice denied Bob", 8001, "1002", "1001", 403),
    ("Protected: Bob reads Bob", 8001, "1002", "1002", 200),
]

results = []

print("=" * 60)
print("AI RED TEAM CYBER RANGE - SECURITY COMPARISON")
print("=" * 60)

for name, port, record_id, user, expected in tests:
    status, data = test_request(port, record_id, user)
    passed = status == expected
    results.append({
        "test": name,
        "expected_status": expected,
        "actual_status": status,
        "passed": passed
    })
    print(f"{'PASS' if passed else 'FAIL'} | {name}")
    print(f"       Expected HTTP {expected}, received HTTP {status}")

passed_count = sum(item["passed"] for item in results)

Path("results").mkdir(exist_ok=True)
with open("results/security_comparison.json", "w") as file:
    json.dump(results, file, indent=2)

print("=" * 60)
print(f"TESTS PASSED: {passed_count}/{len(results)}")
print("Report saved: results/security_comparison.json")
