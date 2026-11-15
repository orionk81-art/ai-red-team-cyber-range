
import json
from pathlib import Path
from improved_classifier import predict

# Fresh evaluation scenarios.
# Do not modify the classifier based on these results
# if you want to preserve this set for evaluation.

scenarios = [
    {
        "id": "EVAL-001",
        "description": "Changing an invoice number lets a customer read a stranger's billing information.",
        "expected": "broken_access_control"
    },
    {
        "id": "EVAL-002",
        "description": "A regular employee can download payroll files reserved for managers.",
        "expected": "broken_access_control"
    },
    {
        "id": "EVAL-003",
        "description": "A website exposes private profiles to visitors who have not signed in.",
        "expected": "broken_access_control"
    },
    {
        "id": "EVAL-004",
        "description": "A crafted search parameter changes the logic of a database lookup.",
        "expected": "sql_injection"
    },
    {
        "id": "EVAL-005",
        "description": "An attacker adds malicious syntax to a login field to bypass a database-backed check.",
        "expected": "sql_injection"
    },
    {
        "id": "EVAL-006",
        "description": "Untrusted form data is concatenated into a query, allowing its intended meaning to change.",
        "expected": "sql_injection"
    },
    {
        "id": "EVAL-007",
        "description": "A public server still uses factory-default administrator credentials.",
        "expected": "insecure_configuration"
    },
    {
        "id": "EVAL-008",
        "description": "A cloud storage container is mistakenly configured for unrestricted public reading.",
        "expected": "insecure_configuration"
    },
    {
        "id": "EVAL-009",
        "description": "A production website exposes its internal diagnostic console.",
        "expected": "insecure_configuration"
    },
    {
        "id": "EVAL-010",
        "description": "An authorized payroll manager downloads an approved report.",
        "expected": "unknown"
    },
    {
        "id": "EVAL-011",
        "description": "A database administrator performs a scheduled query optimization.",
        "expected": "unknown"
    },
    {
        "id": "EVAL-012",
        "description": "A developer disables diagnostic logging before a production release.",
        "expected": "unknown"
    }
]

results = []
correct = 0

print("=" * 55)
print("AI RED TEAM - FRESH EVALUATION")
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

print("\nEVALUATION RESULTS")
print(f"Correct: {correct}/{len(scenarios)}")
print(f"Accuracy: {accuracy:.1f}%")

Path("results").mkdir(exist_ok=True)

with open("results/unseen_evaluation_results.json", "w") as file:
    json.dump({
        "total": len(scenarios),
        "correct": correct,
        "accuracy_percent": accuracy,
        "results": results
    }, file, indent=2)

print("\nSaved: results/unseen_evaluation_results.json")
