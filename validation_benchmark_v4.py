
import json
from pathlib import Path
from datetime import datetime, timezone

from classifier_v4 import predict

# Version 4 fresh validation benchmark
# Freeze classifier_v4.py before running.
# Do not change expected labels after seeing predictions.

scenarios = [
    # Broken access control: 6 cases
    {
        "description": "By altering a URL identifier, a shopper can inspect purchase histories belonging to unrelated customers.",
        "expected": "broken_access_control"
    },
    {
        "description": "A low-privilege operator is able to export financial documents intended exclusively for executives.",
        "expected": "broken_access_control"
    },
    {
        "description": "The API returns a different tenant's medical documents when the requester substitutes a tenant ID.",
        "expected": "broken_access_control"
    },
    {
        "description": "A visitor without an account can inspect internal personnel profiles.",
        "expected": "broken_access_control"
    },
    {
        "description": "Changing a document reference allows a basic user to obtain a supervisor's restricted files.",
        "expected": "broken_access_control"
    },
    {
        "description": "An unauthenticated caller receives another organization's invoices through a predictable endpoint.",
        "expected": "broken_access_control"
    },

    # SQL injection: 6 cases
    {
        "description": "An apostrophe in a product filter unexpectedly changes the SQL WHERE clause.",
        "expected": "sql_injection"
    },
    {
        "description": "User-controlled input is inserted directly into a SELECT statement, modifying its conditions.",
        "expected": "sql_injection"
    },
    {
        "description": "An attacker supplies a UNION SELECT payload and extracts additional rows from a relational datastore.",
        "expected": "sql_injection"
    },
    {
        "description": "The application constructs database commands by joining raw request parameters into executable SQL.",
        "expected": "sql_injection"
    },
    {
        "description": "A search box accepts a tautology payload that makes the backend return every account.",
        "expected": "sql_injection"
    },
    {
        "description": "A crafted ORDER BY expression reveals that untrusted text is executed as part of a query.",
        "expected": "sql_injection"
    },

    # Insecure configuration: 6 cases
    {
        "description": "A storage bucket permits anonymous listing and retrieval of customer backups.",
        "expected": "insecure_configuration"
    },
    {
        "description": "An internet-facing management interface still accepts the vendor's original login credentials.",
        "expected": "insecure_configuration"
    },
    {
        "description": "Detailed stack traces and environment variables are displayed to visitors on production error pages.",
        "expected": "insecure_configuration"
    },
    {
        "description": "A deployment accidentally leaves a diagnostic endpoint accessible to everyone.",
        "expected": "insecure_configuration"
    },
    {
        "description": "The cloud database allows connections from any IP address without network restrictions.",
        "expected": "insecure_configuration"
    },
    {
        "description": "A publicly reachable service exposes its administrative console because access restrictions were disabled.",
        "expected": "insecure_configuration"
    },

    # Legitimate / negative controls: 6 cases
    {
        "description": "A security engineer tests SQL injection defenses in an approved staging environment.",
        "expected": "unknown"
    },
    {
        "description": "An employee downloads a confidential report after receiving explicit authorization.",
        "expected": "unknown"
    },
    {
        "description": "A developer removes factory-default credentials before deploying the server.",
        "expected": "unknown"
    },
    {
        "description": "A database administrator executes a documented maintenance query.",
        "expected": "unknown"
    },
    {
        "description": "A monitoring system alerts when an unauthorized request is blocked by access-control rules.",
        "expected": "unknown"
    },
    {
        "description": "A cloud engineer disables public access to a storage bucket during a security review.",
        "expected": "unknown"
    }
]


def main():
    results = []
    correct = 0

    for index, scenario in enumerate(scenarios, start=1):
        predicted = predict(scenario["description"])
        expected = scenario["expected"]
        passed = predicted == expected

        correct += int(passed)

        results.append({
            "id": index,
            "description": scenario["description"],
            "expected": expected,
            "predicted": predicted,
            "correct": passed
        })

        status = "PASS" if passed else "FAIL"

        print(
            f"{index:02d}. {status} | "
            f"Expected: {expected} | "
            f"Predicted: {predicted}"
        )

    total = len(results)
    accuracy = correct / total if total else 0

    report = {
        "benchmark": "Version 4 fresh validation",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "correct": correct,
        "accuracy": round(accuracy, 4),
        "results": results
    }

    output = Path("results/version4_validation_results.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 55)
    print("VERSION 4 FRESH VALIDATION")
    print("=" * 55)
    print(f"Correct: {correct}/{total}")
    print(f"Accuracy: {accuracy:.1%}")
    print(f"Report saved: {output}")


if __name__ == "__main__":
    main()
