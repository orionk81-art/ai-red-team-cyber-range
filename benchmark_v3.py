
import json
from pathlib import Path

from classifier_v3 import predict
from unseen_evaluation import scenarios

# These scenarios have already been examined during development.
# This is a diagnostic benchmark, NOT an independent test.

LABELS = [
    "broken_access_control",
    "sql_injection",
    "insecure_configuration",
    "unknown"
]

results = []
correct = 0

print("=" * 55)
print("AI RED TEAM - VERSION 3 DIAGNOSTIC BENCHMARK")
print("=" * 55)

for scenario in scenarios:
    expected = scenario["expected"]
    predicted = predict(scenario["description"])
    passed = expected == predicted

    correct += int(passed)

    results.append({
        "id": scenario["id"],
        "description": scenario["description"],
        "expected": expected,
        "predicted": predicted,
        "correct": passed
    })

    status = "PASS" if passed else "FAIL"

    print(
        f"{scenario['id']}: {status} | "
        f"Expected={expected} | Predicted={predicted}"
    )

total = len(results)
accuracy = correct / total if total else 0

# Treat any vulnerability label as a positive detection.
# "unknown" is treated as no vulnerability detected.

true_positive = sum(
    r["expected"] != "unknown"
    and r["predicted"] != "unknown"
    for r in results
)

false_positive = sum(
    r["expected"] == "unknown"
    and r["predicted"] != "unknown"
    for r in results
)

false_negative = sum(
    r["expected"] != "unknown"
    and r["predicted"] == "unknown"
    for r in results
)

true_negative = sum(
    r["expected"] == "unknown"
    and r["predicted"] == "unknown"
    for r in results
)

precision = (
    true_positive / (true_positive + false_positive)
    if true_positive + false_positive else 0
)

recall = (
    true_positive / (true_positive + false_negative)
    if true_positive + false_negative else 0
)

# Calculate accuracy separately for each category.

per_category = {}

for label in LABELS:
    matching = [r for r in results if r["expected"] == label]

    passed = sum(r["correct"] for r in matching)

    per_category[label] = {
        "total": len(matching),
        "correct": passed,
        "accuracy_percent": (
            round(passed / len(matching) * 100, 2)
            if matching else None
        )
    }

report = {
    "benchmark": "version3_diagnostic",
    "independent_evaluation": False,
    "total": total,
    "correct": correct,
    "accuracy_percent": round(accuracy * 100, 2),
    "precision_percent": round(precision * 100, 2),
    "recall_percent": round(recall * 100, 2),
    "confusion_counts": {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative
    },
    "per_category": per_category,
    "results": results
}

print("\nBENCHMARK SUMMARY")
print(f"Accuracy: {accuracy * 100:.1f}%")
print(f"Precision: {precision * 100:.1f}%")
print(f"Recall: {recall * 100:.1f}%")
print(f"False positives: {false_positive}")
print(f"False negatives: {false_negative}")

print("\nPER-CATEGORY RESULTS")

for label, stats in per_category.items():
    print(
        f"{label}: {stats['correct']}/{stats['total']} "
        f"({stats['accuracy_percent']}%)"
    )

Path("results").mkdir(exist_ok=True)

output = Path("results/version3_diagnostic.json")

with output.open("w", encoding="utf-8") as file:
    json.dump(report, file, indent=2)

print(f"\nReport saved: {output}")
