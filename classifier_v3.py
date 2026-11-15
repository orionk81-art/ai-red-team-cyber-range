
import re


# AI Red Team Cyber Range
# Version 3: Explainable, rule-based vulnerability detection

def normalize(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s'-]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def has_any(text, indicators):
    return any(indicator in text for indicator in indicators)


def analyze(description):
    text = normalize(description)
    findings = []

    # Broken access control: unauthorized access to resources
    access_actions = [
        "read", "download", "retrieve", "access",
        "view", "exposes", "obtain"
    ]

    access_resources = [
        "private", "confidential", "payroll", "billing",
        "records", "profiles", "files", "invoice"
    ]

    access_violations = [
        "stranger", "regular employee", "without permission",
        "not signed in", "unauthorized", "reserved for",
        "another user", "different account", "coworker",
        "changing an invoice number"
    ]

    if (
        has_any(text, access_actions)
        and has_any(text, access_resources)
        and has_any(text, access_violations)
    ):
        findings.append((
            "broken_access_control",
            "Resource access appears to bypass authorization."
        ))

    # SQL injection: untrusted input changes database operations
    database_context = [
        "database", "query", "login", "search parameter",
        "form data"
    ]

    injection_behavior = [
        "crafted", "malicious syntax", "concatenated",
        "changes the logic", "bypass", "untrusted",
        "injection", "alter", "manipulat"
    ]

    if (
        has_any(text, database_context)
        and has_any(text, injection_behavior)
    ):
        findings.append((
            "sql_injection",
            "Potential manipulation of database operations."
        ))

    # Insecure configuration: unsafe deployment settings
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
        findings.append((
            "insecure_configuration",
            "Potentially unsafe security configuration."
        ))

    if not findings:
        return {
            "prediction": "unknown",
            "reason": "Insufficient matching security indicators."
        }

    prediction, reason = findings[0]

    return {
        "prediction": prediction,
        "reason": reason
    }


def predict(description):
    return analyze(description)["prediction"]


if __name__ == "__main__":
    examples = [
        "A regular employee can download payroll files reserved for managers.",
        "A crafted search parameter changes the logic of a database lookup.",
        "A public server still uses factory-default administrator credentials.",
        "An authorized manager downloads an approved report."
    ]

    print("=" * 55)
    print("AI RED TEAM - CLASSIFIER VERSION 3")
    print("=" * 55)

    for example in examples:
        result = analyze(example)
        print(f"\nScenario: {example}")
        print(f"Prediction: {result['prediction']}")
        print(f"Reason: {result['reason']}")
