import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError

targets = {
    "Vulnerable application": 8000,
    "Protected application": 8001
}

print("=" * 55)
print("AI RED TEAM CYBER RANGE - NEGATIVE CONTROL")
print("=" * 55)

for name, port in targets.items():
    evidence = 0

    for record_id in ("1001", "1002"):
        url = f"http://127.0.0.1:{port}/record?id={record_id}"
        request = Request(url)

        try:
            with urlopen(request, timeout=5) as response:
                data = json.load(response)
                if response.status == 200 and "secret" in data:
                    evidence += 1
        except HTTPError:
            pass

    finding = evidence == 2
    expected = port == 8000
    passed = finding == expected

    print(f"\nTARGET: {name}")
    print(f"EVIDENCE COUNT: {evidence}")
    print(f"VULNERABILITY DETECTED: {finding}")
    print(f"TEST PASSED: {passed}")
