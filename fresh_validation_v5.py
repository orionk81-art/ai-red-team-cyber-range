
import json
from pathlib import Path
from collections import Counter
from classifier_v5 import predict

# Fresh validation scenarios.
# Do not modify classifier_v5.py before the first run.

scenarios = [
    # Broken access control (10)
    ("broken_access_control", "An ordinary account holder retrieves private invoices belonging to a different organization by guessing invoice numbers."),
    ("broken_access_control", "A guest can read confidential employee profiles without signing in."),
    ("broken_access_control", "Changing the owner identifier in an API request reveals another customer's billing history."),
    ("broken_access_control", "A basic user successfully invokes a supervisor-only approval operation."),
    ("broken_access_control", "A mobile client displays confidential records from unrelated customers after a resource identifier is modified."),
    ("broken_access_control", "An anonymous visitor downloads internal payroll documents through a predictable endpoint."),
    ("broken_access_control", "A student accesses another student's grades by modifying the record number."),
    ("broken_access_control", "A customer can cancel purchases made by someone else without permission."),
    ("broken_access_control", "An unprivileged session retrieves administrator audit logs."),
    ("broken_access_control", "An attacker swaps the account reference and receives another tenant's confidential documents."),

    # SQL injection (10)
    ("sql_injection", "A search field accepts a UNION SELECT payload that exposes database rows."),
    ("sql_injection", "An attacker changes a filter parameter to alter the WHERE clause of a database query."),
    ("sql_injection", "A login form concatenates user-controlled strings directly into an SQL statement."),
    ("sql_injection", "A crafted input changes the application's database query logic."),
    ("sql_injection", "A malicious product ID causes the database to execute unintended commands."),
    ("sql_injection", "An attacker supplies an always-true condition to bypass a database-backed login."),
    ("sql_injection", "An HTTP parameter is inserted into a query without parameter binding, allowing data extraction."),
    ("sql_injection", "A reporting endpoint executes an injected ORDER BY expression."),
    ("sql_injection", "Untrusted form data becomes executable SQL inside a search operation."),
    ("sql_injection", "A manipulated request triggers unauthorized database updates through unsafe query construction."),

    # Insecure configuration (10)
    ("insecure_configuration", "A production management interface is reachable from the internet without authentication."),
    ("insecure_configuration", "A deployed appliance still accepts its factory-default administrator password."),
    ("insecure_configuration", "A diagnostic endpoint exposes environment variables to unauthenticated visitors."),
    ("insecure_configuration", "The web server allows anonymous directory listing of sensitive files."),
    ("insecure_configuration", "A production application exposes detailed stack traces and internal paths."),
    ("insecure_configuration", "The firewall was disabled, leaving the administrative console accessible from any IP address."),
    ("insecure_configuration", "A public cloud storage container permits unrestricted reading of confidential backups."),
    ("insecure_configuration", "An administrator accidentally enables debug mode on the public production website."),
    ("insecure_configuration", "A database dashboard is exposed to the internet with no network restrictions."),
    ("insecure_configuration", "The server's security controls were disabled, exposing a sensitive diagnostic console."),

    # Legitimate or insufficient evidence (10)
    ("unknown", "A developer removes default credentials before deploying the application."),
    ("unknown", "An employee downloads a report explicitly authorized for their account."),
    ("unknown", "A security engineer disables debug mode on the production server."),
    ("unknown", "An administrator blocks external access to the management interface."),
    ("unknown", "A database developer uses prepared statements to safely process search input."),
    ("unknown", "A tester reviews SQL syntax in an isolated training exercise."),
    ("unknown", "An approved staging environment runs a diagnostic console for internal testing."),
    ("unknown", "A security review documents a previously exposed endpoint that has now been fixed."),
    ("unknown", "An authorized analyst accesses audit logs using an approved administrative account."),
    ("unknown", "A system administrator patches a misconfigured service and verifies that access restrictions are restored."),
]

results = []

for index, (expected, description) in enumerate(scenarios, 1):
    predicted = predict(description)
    correct = predicted == expected

    results.append({
        "id": index,
        "description": description,
        "expected": expected,
        "predicted": predicted,
        "correct": correct
    })

    status = "PASS" if correct else "FAIL"
    print(f"{index:02d}. {status} | Expected: {expected} | Predicted: {predicted}")

correct_count = sum(item["correct"] for item in results)
total = len(results)
accuracy = correct_count / total if total else 0

false_positives = sum(
    item["expected"] == "unknown" and item["predicted"] != "unknown"
    for item in results
)

false_negatives = sum(
    item["expected"] != "unknown" and item["predicted"] == "unknown"
    for item in results
)

wrong_categories = sum(
    item["expected"] != "unknown"
    and item["predicted"] != "unknown"
    and item["expected"] != item["predicted"]
    for item in results
)

report = {
    "version": "5",
    "evaluation": "fresh_first_run",
    "total": total,
    "correct": correct_count,
    "accuracy_percent": round(accuracy * 100, 2),
    "false_positives": false_positives,
    "false_negatives": false_negatives,
    "wrong_categories": wrong_categories,
    "results": results
}

output = Path("results/version5_fresh_validation.json")
output.parent.mkdir(parents=True, exist_ok=True)

# Preserve the first-run report if this script is rerun.
if output.exists():
    print(f"\nExisting report preserved: {output}")
else:
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nFirst-run report saved: {output}")

print("\n========== VERSION 5 FRESH VALIDATION ==========")
print(f"Correct:          {correct_count}/{total}")
print(f"Accuracy:         {accuracy:.1%}")
print(f"False positives:  {false_positives}")
print(f"False negatives:  {false_negatives}")
print(f"Wrong categories: {wrong_categories}")
print("================================================")
