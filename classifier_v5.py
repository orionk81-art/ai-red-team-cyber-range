
import re

# AI Red Team Cyber Range
# Version 5: Context-aware, rule-based vulnerability classifier

CATEGORIES = (
    "broken_access_control",
    "sql_injection",
    "insecure_configuration",
)

PATTERNS = {
    "broken_access_control": [
        r"\banother (?:user|customer|tenant|organization|company)",
        r"\bdifferent tenant",
        r"\bunrelated customers",
        r"\bwithout (?:permission|authorization|an account)",
        r"\bunauthenticated",
        r"\bsigned.out",
        r"\blow.privilege",
        r"\brestricted (?:files|records|documents)",
        r"\bintended exclusively for",
        r"\bbelonging to another",
        r"\bsubstitut(?:es|ing|ed) (?:a |the )?tenant id",
        r"\bchanging a document reference",
        r"\baltering a url identifier",
        r"\bpredictable endpoint",
    ],
    "sql_injection": [
        r"\bsql (?:injection|syntax|where|statement)",
        r"\bunion select",
        r"\bselect statement",
        r"\border by expression",
        r"\btautology payload",
        r"\braw request parameters",
        r"\bexecutable sql",
        r"\bquery (?:logic|conditions)",
        r"\bdatabase (?:query|commands|statement)",
        r"\binjected (?:conditions|sql|syntax)",
        r"\bcrafted (?:input|search parameter)",
        r"\buntrusted (?:input|text|form data)",
    ],
    "insecure_configuration": [
        r"\bfactory.default",
        r"\bdefault credentials",
        r"\bvendor.s original login credentials",
        r"\bdiagnostic (?:console|endpoint)",
        r"\bmanagement interface",
        r"\badministrative console",
        r"\bpublic(?:ly)? (?:reachable|accessible|reading)",
        r"\banonymous (?:listing|access)",
        r"\bunrestricted public",
        r"\baccess restrictions were disabled",
        r"\bwithout network restrictions",
        r"\bany ip address",
        r"\bstack traces",
        r"\benvironment variables",
        r"\bdebug (?:mode|settings)",
        r"\bmisconfigured",
    ],
}

# These expressions identify common descriptions of successful
# security controls or remediation, not proof of safety.
REMEDIATION = [
    r"\bremov(?:e|es|ed|ing)\b",
    r"\bdisabl(?:e|es|ed|ing)\b",
    r"\bblock(?:s|ed|ing)?\b",
    r"\bprevent(?:s|ed|ing)?\b",
    r"\bfix(?:es|ed|ing)?\b",
    r"\bpatch(?:es|ed|ing)?\b",
    r"\bmitigat(?:e|es|ed|ing)\b",
]

LEGITIMATE_CONTEXT = [
    r"\bexplicit authorization",
    r"\bapproved staging environment",
    r"\bauthorized monitoring",
    r"\bdocumented maintenance",
    r"\bsecurity review",
]


def normalize(description):
    text = str(description).lower()
    text = re.sub(r"[^a-z0-9\s'-]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def matched_patterns(text, patterns):
    return [
        pattern
        for pattern in patterns
        if re.search(pattern, text, flags=re.IGNORECASE)
    ]


def analyze(description):
    text = normalize(description)

    if not text:
        return {
            "prediction": "unknown",
            "reason": "No description provided.",
            "findings": [],
        }

    findings = []

    for category in CATEGORIES:
        matches = matched_patterns(text, PATTERNS[category])

        if matches:
            findings.append({
                "category": category,
                "reason": "Matched contextual security indicators.",
                "evidence": matches,
            })

    remediation = matched_patterns(text, REMEDIATION)
    legitimate = matched_patterns(text, LEGITIMATE_CONTEXT)

    # Disabling a protective control is a vulnerability,
    # not a security improvement.
    disabled_protection = bool(re.search(
        r"\b(?:access restrictions|security controls|"
        r"authentication|authorization|firewall rules)"
        r"\s+(?:were|was|are|is)?\s*disabled\b",
        text
    ))

    if disabled_protection:
        remediation = []
        legitimate = []


    # Conservative rule: when explicit remediation or authorized
    # activity is described, abstain rather than raise an alert.
    # This can miss real vulnerabilities in mixed descriptions.
    if remediation or legitimate:
        return {
            "prediction": "unknown",
            "reason": "Possible remediation or authorized activity; "
                      "manual review may be required.",
            "findings": [],
            "suppressed_findings": findings,
        }

    if not findings:
        return {
            "prediction": "unknown",
            "reason": "Insufficient matching security indicators.",
            "findings": [],
        }

    return {
        "prediction": findings[0]["category"],
        "reason": findings[0]["reason"],
        "findings": findings,
    }


def predict(description):
    return analyze(description)["prediction"]


if __name__ == "__main__":
    examples = [
        "A user changes a URL and accesses another tenant's records.",
        "An attacker supplies a UNION SELECT payload.",
        "A production server exposes a diagnostic console.",
        "A developer removes factory-default credentials.",
        "An employee downloads an approved report.",
    ]

    print("=" * 55)
    print("AI RED TEAM - CLASSIFIER VERSION 5")
    print("=" * 55)

    for example in examples:
        result = analyze(example)
        print(f"\nScenario: {example}")
        print(f"Prediction: {result['prediction']}")
        print(f"Reason: {result['reason']}")
        print(f"Findings: {len(result['findings'])}")
