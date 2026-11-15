from improved_classifier import predict

import json
from pathlib import Path



# New scenarios not used in the original benchmark
scenarios = [
    {
        "id": "HOLD-001",
        "description": "An employee retrieves a coworker's confidential records by changing a record ID.",
        "expected": "broken_access_control"
    },
    {
        "id": "HOLD-002",
        "description": "A customer accesses another user's private account.",
        "expected": "broken_access_control"
    },
    {
        "id": "HOLD-003",
        "description": "A visitor downloads private documents belonging to a different account.",
        "expected": "broken_access_control"
    },
    {
        "id": "HOLD-004",
        "description": "An attacker manipulates a database query using crafted input.",
        "expected": "sql_injection"
    },
    {
        "id": "HOLD-005",
        "description": "A login form allows SQL injection through unsanitized input.",
        "expected": "sql_injection"
    },
    {
        "id": "HOLD-006",
        "description": "User-controlled values alter the structure of a database statement.",
        "expected": "sql_injection"
    },
    {
        "id": "HOLD-007",
        "description": "A production server reveals detailed error traces and internal settings.",
        "expected": "insecure_configuration"
    },
    {
        "id": "HOLD-008",
        "description": "An administrator accidentally enables debug mode on a public website.",
        "expected": "insecure_configuration"
    },
    {
        "id": "HOLD-009",
        "description": "A deployed application exposes sensitive configuration details.",
        "expected": "insecure_configuration"
    },
    {
        "id": "HOLD-010",
        "description": "A user successfully resets their own password.",
        "expected": "unknown"
    },
    {
        "id": "HOLD-011",
        "description": "A system administrator applies approved security updates.",
        "expected": "unknown"
    },
    {
        "id": "HOLD-012",
        "description": "A network monitoring dashboard displays normal traffic.",
        "expected": "unknown"
    }
]


results = []
correct = 0

print("=" * 55)
print("AI RED TEAM - HELD-OUT BENCHMARK")
print("=" * 55)

for scenario in scenarios:
    prediction = predict(scenario["description"])
    passed = prediction == scenario["expected"]

    if passed:
        correct += 1

    results.append({
        **scenario,
        "prediction": prediction,
        "correct": passed
    })

    print(
        f'{scenario["id"]}: '
        f'Predicted={prediction} | '
        f'Expected={scenario["expected"]} | '
        f'Correct={passed}'
    )

accuracy = correct / len(scenarios) * 100

print("\nBENCHMARK RESULTS")
print(f"Correct: {correct}/{len(scenarios)}")
print(f"Accuracy: {accuracy:.1f}%")

Path("results").mkdir(exist_ok=True)

with open("results/held_out_results.json", "w") as file:
    json.dump({
        "total": len(scenarios),
        "correct": correct,
        "accuracy_percent": accuracy,
        "results": results
    }, file, indent=2)

print("\nSaved: results/held_out_results.json")
# Existing rule-based security classifier

