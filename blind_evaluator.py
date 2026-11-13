import json
from pathlib import Path

scenarios = [
    {
        "id": "SEC-001",
        "description": "A user can view another user's private records.",
        "expected": "broken_access_control"
    },
    {
        "id": "SEC-002",
        "description": "User input is inserted directly into SQL queries.",
        "expected": "sql_injection"
    },
    {
        "id": "SEC-003",
        "description": "A production application exposes debug mode.",
        "expected": "insecure_configuration"
    }
]

def predict(description):
    text = description.lower()

    if "another user's" in text:
        return "broken_access_control"
    if "sql" in text:
        return "sql_injection"
    if "debug" in text:
        return "insecure_configuration"

    return "unknown"

results = []

print("AI RED TEAM CYBER RANGE - BLIND EVALUATION")
print("=" * 50)

for scenario in scenarios:
    prediction = predict(scenario["description"])
    correct = prediction == scenario["expected"]

    results.append({
        "scenario": scenario["id"],
        "prediction": prediction,
        "correct": correct
    })

    print(f"{scenario['id']}: {prediction} | Correct: {correct}")

accuracy = sum(r["correct"] for r in results) / len(results) * 100

print(f"\nBASELINE ACCURACY: {accuracy:.1f}%")

Path("results").mkdir(exist_ok=True)

with open("results/blind_results.json", "w") as file:
    json.dump(results, file, indent=2)

print("Results saved successfully.")
