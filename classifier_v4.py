
import re

# AI Red Team Cyber Range
# Version 4: Improved explainable vulnerability classifier


def normalize(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s'-]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def has_any(text, indicators):
    """Match complete words and phrases."""
    return any(
        re.search(r"(?<!\w)" + re.escape(item) + r"(?!\w)", text)
        for item in indicators
    )


def analyze(description):
    text = normalize(description)
    findings = []

    # Broken access control
    access_actions = [
        "read", "reads", "download", "downloads",
        "retrieve", "retrieves", "access", "accesses",
        "view", "views", "exposes", "obtain", "obtains"
    ]

    access_resources = [
        "private", "confidential", "payroll", "billing",
        "records", "profiles", "files", "invoice",
        "statement", "statements"
    ]

    access_violations = [
        "stranger", "regular employee", "ordinary staff",
        "without permission", "not signed in", "signed-out",
        "unauthorized", "reserved for", "restricted",
        "another user", "another customer",
        "another department", "another company",
        "different account", "coworker",
        "changing an invoice number",
        "changes an invoice number",
        "modifies the account identifier"
    ]

    if (
        has_any(text, access_actions)
        and has_any(text, access_resources)
        and has_any(text, access_violations)
    ):
        findings.append({
            "category": "broken_access_control",
            "reason": "Resource access appears to bypass authorization."
        })

    # SQL injection
    database_context = [
        "database", "query", "login",
        "search parameter", "form data"
    ]

    injection_behavior = [
        "crafted", "malicious syntax", "concatenated",
        "changes the logic", "bypass", "untrusted",
        "injection", "injected", "injects",
        "alter", "alters", "manipulate",
        "manipulates", "manipulation"
    ]

    if (
        has_any(text, database_context)
        and has_any(text, injection_behavior)
    ):
        findings.append({
            "category": "sql_injection",
            "reason": "Potential manipulation of database operations."
        })

    # Insecure configuration
    configuration_context = [
        "server", "cloud storage", "production",
        "website", "administrator credentials",
        "diagnostic console"
    ]

    unsafe_settings = [
        "factory-default", "unrestricted public",
        "exposes", "misconfigured", "enabled debug",
        "default credentials", "public reading"
    ]

    if (
        has_any(text, configuration_context)
        and has_any(text, unsafe_settings)
    ):
        findings.append({
            "category": "insecure_configuration",
            "reason": "Potentially unsafe security configuration."
        })

    if not findings:
        return {
            "prediction": "unknown",
            "reason": "Insufficient matching security indicators.",
            "findings": []
        }

    return {
        "prediction": findings[0]["category"],
        "reason": findings[0]["reason"],
        "findings": findings
    }


def predict(description):
    return analyze(description)["prediction"]


if __name__ == "__main__":
    examples = [
        "A regular employee can download payroll files reserved for managers.",
        "A crafted search parameter changes the logic of a database lookup.",
        "A public server still uses factory-default administrator credentials.",
        "An authorized manager downloads an approved report.",
        "The user already completed the onboarding process."
    ]

    print("=" * 55)
    print("AI RED TEAM - CLASSIFIER VERSION 4")
    print("=" * 55)

    for example in examples:
        result = analyze(example)
        print(f"\nScenario: {example}")
        print(f"Prediction: {result['prediction']}")
        print(f"Reason: {result['reason']}")
        print(f"Findings: {len(result['findings'])}")
