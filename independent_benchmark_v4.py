
import json
from pathlib import Path
from datetime import datetime, timezone

from classifier_v4 import predict

# Independent evaluation set for Version 4.
# Freeze these scenarios before reviewing the results.
# Do not edit the expected labels to improve the score.

scenarios = [
    # Broken access control
    {
        "description": "A customer modifies the account identifier in a request and downloads another customer's confidential statement.",
        "expected": "broken_access_control"
    },
    {
        "description": "A guest retrieves private employee records without permission.",
        "expected": "broken_access_control"
    },
    {
        "description": "An ordinary staff member views restricted payroll files belonging to another department.",
        "expected": "broken_access_control"
    },
    {
        "description": "A user changes an invoice number and obtains another company's billing records.",
        "expected": "broken_access_control"
    },
    {
        "description": "A signed-out visitor can read confidential customer profiles.",
        "expected": "broken_access_control"
    },

    # SQL injection
    {
        "description": "A crafted search parameter alters the database query and returns unintended rows.",
        "expected": "sql_injection"
    },
    {
        "description": "Untrusted form data is concatenated into a database statement, allowing an attacker to manipulate its logic.",
        "expected": "sql_injection"
    },
    {
        "description": "An attacker injects SQL syntax into a login field to bypass the database authentication check.",
        "expected": "sql_injection"
    },
    {
        "description": "A malicious database query uses injected conditions to retrieve unauthorized information.",
        "expected": "sql_injection"
    },
    {
        "description": "A crafted input changes the logic of a database search operation.",
        "expected": "sql_injection"
    },

    # Insecure configuration
    {
        "description": "A production server exposes a diagnostic console with unrestricted public access.",
        "expected": "insecure_configuration"
    },
    {
        "description": "A cloud storage service is misconfigured to permit public reading of sensitive files.",
        "expected": "insecure_configuration"
    },
    {
        "description": "A website runs with enabled debug settings in production.",
        "expected": "insecure_configuration"
    },
    {
        "description": "A server retains factory-default administrator credentials.",
        "expected": "insecure_configuration"
    },
    {
        "description": "A production website exposes default credentials through an unsafe configuration.",
        "expected": "insecure_configuration"
    },

    # Legitimate / negative controls
    {
        "description": "An employee accesses their own approved payroll report.",
        "expected": "unknown"
    },
    {
        "description": "A database administrator reviews query performance using an authorized monitoring dashboard.",
        "expected": "unknown"
    },
    {
        "description": "A customer changes their password using the normal account recovery process.",
        "expected": "unknown"
    },
    {
        "description": "A developer disables debug mode before deploying a website to production.",
        "expected": "unknown"
    },
    {
        "description": "An administrator updates server credentials according to the organization's security policy.",
        "expected": "unknown"
    }
]


def main():
    results = []
    correct = 0

    for index, scenario in enumerate(scenarios, start=1):
        actual = predict(scenario["description"])
        expected = scenario["expected"]
        passed = actual == expected

        if passed:
            correct += 1

        results.append({
            "id": index,
            "description": scenario["description"],
            "expected": expected,
            "predicted": actual,
            "correct": passed
        })

        status = "PASS" if passed else "FAIL"
        print(
            f"{index:02d}. {status} | "
            f"Expected: {expected} | Predicted: {actual}"
        )

    total = len(scenarios)
    accuracy = correct / total if total else 0

    report = {
        "benchmark": "Version 4 initial independent evaluation",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "correct": correct,
        "accuracy": round(accuracy, 4),
        "results": results
    }

    output = Path("results/independent_benchmark_v4.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 55)
    print("VERSION 4 INDEPENDENT BENCHMARK")
    print("=" * 55)
    print(f"Correct: {correct}/{total}")
    print(f"Accuracy: {accuracy:.1%}")
    print(f"Report saved: {output}")


if __name__ == "__main__":
    main()
