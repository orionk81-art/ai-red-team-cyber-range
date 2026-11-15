
import json
from pathlib import Path
from collections import Counter
from classifier_v6 import predict

# AI Red Team Cyber Range
# Version 6 - First-run challenge benchmark
#
# 60 new, manually authored scenarios.
# Do not modify classifier_v6.py before the first run.
#
# This is a synthetic challenge set, not a representative
# sample of real-world vulnerabilities.

scenarios = [
    # BROKEN ACCESS CONTROL (15)
    ("broken_access_control", "A regular employee opens the finance director's confidential expense records by changing an object reference."),
    ("broken_access_control", "A visitor with no active session retrieves private medical appointment details from a patient portal."),
    ("broken_access_control", "A standard account successfully executes a function reserved for system administrators."),
    ("broken_access_control", "A user replaces the numeric identifier in a download link and receives a stranger's tax document."),
    ("broken_access_control", "An unauthenticated caller obtains a list of internal staff salaries through an API."),
    ("broken_access_control", "A customer modifies an order reference to view another household's purchase history."),
    ("broken_access_control", "A read-only account successfully deletes records that should require elevated privileges."),
    ("broken_access_control", "A member of one project team reads confidential files assigned exclusively to a separate team."),
    ("broken_access_control", "A browser request omits the session cookie but still returns private account information."),
    ("broken_access_control", "A guest user invokes an administrative function despite lacking the required role."),
    ("broken_access_control", "An attacker cycles through sequential document IDs and downloads other people's contracts."),
    ("broken_access_control", "A junior employee changes a role parameter and gains access to executive payroll."),
    ("broken_access_control", "A user alters a workspace identifier and sees messages belonging to a competing company."),
    ("broken_access_control", "An ordinary subscriber can modify another subscriber's saved payment methods."),
    ("broken_access_control", "An external visitor accesses a restricted internal dashboard without being authenticated."),

    # SQL INJECTION (15)
    ("sql_injection", "A product search concatenates unchecked text into a database command, changing which rows are returned."),
    ("sql_injection", "A malicious request appends an extra SQL predicate to the application's login lookup."),
    ("sql_injection", "A numeric query-string parameter is interpreted as part of a database expression rather than as data."),
    ("sql_injection", "A search box accepts quote characters that terminate a string literal and alter a backend SELECT."),
    ("sql_injection", "A crafted customer name modifies the database WHERE condition and reveals hidden entries."),
    ("sql_injection", "An attacker manipulates a sorting parameter to inject a database expression."),
    ("sql_injection", "A web form passes unsanitized input into dynamically assembled SQL, allowing unintended record changes."),
    ("sql_injection", "A hostile filter value causes the database to evaluate an attacker-supplied boolean expression."),
    ("sql_injection", "A reporting tool builds SQL by joining raw request values into a query string."),
    ("sql_injection", "A login endpoint accepts a quote-and-comment sequence that bypasses its password comparison."),
    ("sql_injection", "An injected subquery retrieves confidential customer rows through a vulnerable search endpoint."),
    ("sql_injection", "A parameter intended to hold a number instead contains SQL operators and changes the query result."),
    ("sql_injection", "An application interpolates an untrusted username into a SELECT command without using bound parameters."),
    ("sql_injection", "A malicious URL parameter alters the SQL ORDER BY clause used to sort results."),
    ("sql_injection", "An attacker supplies a crafted input that makes a database execute a second unintended statement."),

    # INSECURE CONFIGURATION (15)
    ("insecure_configuration", "A production control panel is accessible on the public internet using a vendor-supplied password."),
    ("insecure_configuration", "A cloud object bucket grants read permission to everyone, exposing archived customer files."),
    ("insecure_configuration", "A server publishes its diagnostic status page with sensitive runtime settings visible to visitors."),
    ("insecure_configuration", "An administrative service listens on all interfaces with no authentication requirement."),
    ("insecure_configuration", "A newly deployed appliance retains the manufacturer's initial login combination."),
    ("insecure_configuration", "A web application displays internal exception details and file paths to anonymous users."),
    ("insecure_configuration", "A storage share is configured for worldwide access even though it contains confidential backups."),
    ("insecure_configuration", "A deployment accidentally leaves a troubleshooting interface available outside the corporate network."),
    ("insecure_configuration", "A production server permits unrestricted browsing of folders containing private documents."),
    ("insecure_configuration", "An operations dashboard can be reached by anyone because network filtering was turned off."),
    ("insecure_configuration", "A public-facing database administration page uses a blank password."),
    ("insecure_configuration", "A development-only diagnostic route remains enabled on the live customer service."),
    ("insecure_configuration", "A cloud firewall rule allows unrestricted inbound connections to a sensitive management port."),
    ("insecure_configuration", "A deployed website exposes configuration secrets through a publicly accessible status endpoint."),
    ("insecure_configuration", "A server's authentication checks are turned off, leaving its management interface open to outsiders."),

    # LEGITIMATE / INSUFFICIENT EVIDENCE (15)
    ("unknown", "A security engineer reviews a proposed firewall change without applying it."),
    ("unknown", "A developer demonstrates SQL injection concepts using an isolated, nonproduction training database."),
    ("unknown", "A customer downloads an invoice assigned to their own authenticated account."),
    ("unknown", "An administrator replaces a vendor password with a unique credential before installation."),
    ("unknown", "A monitoring system records a failed attempt to access a restricted administrative endpoint."),
    ("unknown", "A tester submits a UNION SELECT string to a local practice application during an approved exercise."),
    ("unknown", "A production team confirms that a management interface is reachable only through the corporate VPN."),
    ("unknown", "A database application uses parameterized queries to prevent attacker input from changing SQL logic."),
    ("unknown", "An authorized payroll manager views employee salary information as part of normal duties."),
    ("unknown", "A web server returns a 403 response when an unauthenticated visitor requests private documents."),
    ("unknown", "An engineer disables a publicly reachable debug console before releasing the service."),
    ("unknown", "A developer writes documentation describing how SQL statements are constructed."),
    ("unknown", "A security analyst investigates a reported exposed dashboard but finds no public access."),
    ("unknown", "An internal application permits anonymous access to a deliberately public help page."),
    ("unknown", "A maintenance worker rotates default credentials and verifies that remote administration requires authentication."),
]

def evaluate():
    results = []

    for index, (expected, description) in enumerate(scenarios, 1):
        predicted = predict(description)

        results.append({
            "id": index,
            "description": description,
            "expected": expected,
            "predicted": predicted,
            "correct": expected == predicted
        })

    total = len(results)
    correct = sum(item["correct"] for item in results)

    false_positives = sum(
        item["expected"] == "unknown"
        and item["predicted"] != "unknown"
        for item in results
    )

    false_negatives = sum(
        item["expected"] != "unknown"
        and item["predicted"] == "unknown"
        for item in results
    )

    wrong_categories = sum(
        item["expected"] != "unknown"
        and item["predicted"] != "unknown"
        and item["expected"] != item["predicted"]
        for item in results
    )

    categories = (
        "broken_access_control",
        "sql_injection",
        "insecure_configuration",
        "unknown",
    )

    per_category = {}

    for category in categories:
        subset = [
            item for item in results
            if item["expected"] == category
        ]
        per_category[category] = {
            "total": len(subset),
            "correct": sum(item["correct"] for item in subset),
        }

    report = {
        "version": "6",
        "evaluation": "first_run_synthetic_challenge",
        "total": total,
        "correct": correct,
        "accuracy_percent": round(correct / total * 100, 2),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "wrong_categories": wrong_categories,
        "per_category": per_category,
        "results": results,
    }

    output = Path("results/version6_independent_validation.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    # Preserve the first-run report.
    if output.exists():
        print(f"Existing report preserved: {output}")
    else:
        output.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8"
        )
        print(f"First-run report saved: {output}")

    print("\n" + "=" * 55)
    print("VERSION 6 - FIRST-RUN CHALLENGE BENCHMARK")
    print("=" * 55)
    print(f"Correct:          {correct}/{total}")
    print(f"Accuracy:         {correct / total:.1%}")
    print(f"False positives:  {false_positives}")
    print(f"False negatives:  {false_negatives}")
    print(f"Wrong categories: {wrong_categories}")

    print("\nPER-CATEGORY RESULTS")
    for category, counts in per_category.items():
        print(
            f"{category}: "
            f"{counts['correct']}/{counts['total']}"
        )

    print("\nFAILED SCENARIOS")
    failures = [item for item in results if not item["correct"]]

    if not failures:
        print("None")
    else:
        for item in failures:
            print(
                f"{item['id']:02d}. "
                f"Expected: {item['expected']} | "
                f"Predicted: {item['predicted']}"
            )

    print("=" * 55)


if __name__ == "__main__":
    evaluate()
