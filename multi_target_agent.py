import json
from pathlib import Path
from urllib.request import urlopen
from urllib.error import HTTPError

TARGETS = [
    {"name": "Vulnerable", "port": 8000, "expected": True},
    {"name": "Protected", "port": 8001, "expected": False}
]

def inspect_record(port, record_id):
    url = f"http://127.0.0.1:{port}/record?id={record_id}"
    try:
        with urlopen(url, timeout=5) as response:
            data = json.load(response)
            return response.status, data
    except HTTPError as error:
        return error.code, {}

def run_agent(target):
    evidence = []
    observations = []

    for record_id in ("1001", "1002"):
        status, data = inspect_record(target["port"], record_id)
        observations.append({
            "record_id": record_id,
            "http_status": status
        })

        if status == 200 and "secret" in data:
            evidence.append(record_id)

    predicted = len(evidence) == 2
    correct = predicted == target["expected"]

    return {
        "target": target["name"],
        "prediction": predicted,
        "expected": target["expected"],
        "correct": correct,
        "score": 100 if correct else 0,
        "observations": observations
    }

results = []

print("=" * 55)
print("AI RED TEAM CYBER RANGE - MULTI-TARGET AGENT")
print("=" * 55)

for target in TARGETS:
    result = run_agent(target)
    results.append(result)

    print(f"\nTARGET: {result['target']}")
    print(f"PREDICTED VULNERABILITY: {result['prediction']}")
    print(f"EXPECTED: {result['expected']}")
    print(f"CORRECT: {result['correct']}")
    print(f"SCORE: {result['score']}/100")

Path("results").mkdir(exist_ok=True)
with open("results/multi_target_agent.json", "w") as file:
    json.dump(results, file, indent=2)

print("\nSaved: results/multi_target_agent.json")
