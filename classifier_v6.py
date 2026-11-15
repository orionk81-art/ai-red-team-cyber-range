
import re

# AI Red Team Cyber Range
# Version 6: Evidence-weighted, rule-based vulnerability classifier

CATEGORIES = (
    "broken_access_control",
    "sql_injection",
    "insecure_configuration",
)

# Each rule contains a regex and its evidence weight.
RULES = {
    "broken_access_control": [
        (r"\banother (?:user|customer|tenant|organization|company|student)", 3),
        (r"\banother student's", 4),
        (r"\bdifferent (?:tenant|organization)", 3),
        (r"\bunrelated customers", 4),
        (r"\bbelonging to a different organization", 4),
        (r"\bbelonging to another", 3),
        (r"\bwithout (?:permission|authorization|signing in)", 2),
        (r"\bguest can read confidential", 4),
        (r"\bsupervisor.only", 4),
        (r"\b(?:basic|ordinary|unprivileged) (?:user|session)", 2),
        (r"\badministrator audit logs", 3),
        (r"\bmodifying (?:the )?record number", 3),
        (r"\bguessing invoice numbers", 3),
        (r"\bchanging (?:the )?owner identifier", 4),
        (r"\bunauthorized (?:access|retrieval)", 3),
        (r"\baccesses? another", 4),
        (r"\banonymous visitor downloads", 3),
        (r"\bpredictable endpoint", 2),
        (r"\brestricted (?:files|records|documents)", 2),
        (r"\b(?:low.privilege|unprivileged)", 2),
        (r"\bsubstitut(?:es|ing|ed) (?:a |the )?tenant id", 4),
        (r"\baltering a url identifier", 3),
        (r"\bchanging a document reference", 3),
    ],

    "sql_injection": [
        (r"\bsql injection", 6),
        (r"\bunion select", 6),
        (r"\btautology payload", 5),
        (r"\bexecutable sql", 5),
        (r"\binjected (?:conditions|sql|syntax)", 5),
        (r"\border by expression", 4),
        (r"\bsql statement", 3),
        (r"\bdatabase query logic", 4),
        (r"\bquery (?:logic|conditions|construction)", 3),
        (r"\bunsafe query construction", 5),
        (r"\bwithout parameter binding", 5),
        (r"\bconcatenat(?:es|ed|ing).*sql", 5),
        (r"\b(?:always.true|tautology) condition", 4),
        (r"\bdatabase.backed login", 3),
        (r"\bexecute unintended commands", 5),
        (r"\bunauthorized database updates", 5),
        (r"\buntrusted form data", 3),
        (r"\bcrafted input", 2),
        (r"\bdatabase (?:query|commands|statement)", 2),
        (r"\braw request parameters", 3),
        (r"\bselect statement", 3),
    ],

    "insecure_configuration": [
        (r"\bfactory.default", 4),
        (r"\bdefault credentials", 5),
        (r"\bfactory.default administrator password", 6),
        (r"\bdiagnostic (?:console|endpoint)", 5),
        (r"\bmanagement interface", 3),
        (r"\badministrative console", 4),
        (r"\bpublic(?:ly)? (?:reachable|accessible|reading)", 3),
        (r"\bexposed to the internet", 4),
        (r"\bwithout authentication", 3),
        (r"\banonymous directory listing", 6),
        (r"\banonymous (?:listing|access)", 4),
        (r"\bunrestricted reading", 5),
        (r"\bpublic cloud storage", 3),
        (r"\bconfidential backups", 3),
        (r"\bfirewall was disabled", 6),
        (r"\bsecurity controls were disabled", 6),
        (r"\baccess restrictions were disabled", 6),
        (r"\bno network restrictions", 5),
        (r"\bwithout network restrictions", 5),
        (r"\bany ip address", 3),
        (r"\bstack traces", 4),
        (r"\benvironment variables", 4),
        (r"\bdebug mode", 3),
        (r"\bmisconfigured", 3),
        (r"\bdatabase dashboard", 4),
        (r"\bweb server allows anonymous", 5),
    ],
}

# Specific descriptions of successful remediation.
REMEDIATION_RULES = [
    r"\bremov(?:e|es|ed|ing) (?:the )?(?:default|factory.default) credentials",
    r"\bdisabl(?:e|es|ed|ing) debug mode",
    r"\bblock(?:s|ed|ing)? external access",
    r"\bpatch(?:es|ed|ing)? a misconfigured service",
    r"\baccess restrictions are restored",
    r"\bhas now been fixed",
    r"\buses? prepared statements",
]

# Explicitly authorized or non-exploit contexts.
LEGITIMATE_RULES = [
    r"\bexplicitly authorized",
    r"\bapproved administrative account",
    r"\bapproved staging environment",
    r"\bauthorized monitoring",
    r"\bdocumented maintenance",
    r"\bisolated training exercise",
    r"\bsecurity review documents",
]

# Disabling a security control is not remediation.
DISABLED_PROTECTION = [
    r"\bfirewall (?:was|is|were|has been) disabled",
    r"\bsecurity controls (?:were|are|have been) disabled",
    r"\baccess restrictions (?:were|are|have been) disabled",
    r"\bauthentication (?:was|is|has been) disabled",
    r"\bauthorization (?:was|is|has been) disabled",
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
        matches = [
            {"pattern": pattern, "weight": weight}
            for pattern, weight in RULES[category]
            if re.search(pattern, text, flags=re.IGNORECASE)
        ]

        if matches:
            findings.append({
                "category": category,
                "score": sum(match["weight"] for match in matches),
                "evidence": matches,
            })

    remediation = matched_patterns(text, REMEDIATION_RULES)
    legitimate = matched_patterns(text, LEGITIMATE_RULES)
    disabled_protection = matched_patterns(text, DISABLED_PROTECTION)

    # Explicitly authorized activity or completed remediation
    # can justify abstaining, unless a disabled security control
    # is also described. Mixed cases still require manual review.
    if (remediation or legitimate) and not disabled_protection:
        return {
            "prediction": "unknown",
            "reason": "Authorized activity or remediation detected; "
                      "manual review may be required.",
            "findings": [],
            "suppressed_findings": findings,
        }

    if not findings:
        return {
            "prediction": "unknown",
            "reason": "Insufficient evidence to classify.",
            "findings": [],
        }

    # Select the category with the highest evidence score.
    # Ties follow the order in CATEGORIES.
    findings.sort(
        key=lambda item: (-item["score"], CATEGORIES.index(item["category"]))
    )

    winner = findings[0]

    return {
        "prediction": winner["category"],
        "reason": "Highest weighted rule evidence.",
        "findings": findings,
    }


def predict(description):
    return analyze(description)["prediction"]


if __name__ == "__main__":
    examples = [
        "A user accesses another tenant's records.",
        "An attacker supplies a UNION SELECT payload.",
        "A production server exposes a diagnostic console.",
        "A developer removes factory-default credentials.",
        "An employee downloads an explicitly authorized report.",
        "The firewall was disabled, exposing an administrative console.",
    ]

    print("=" * 55)
    print("AI RED TEAM - CLASSIFIER VERSION 6")
    print("=" * 55)

    for example in examples:
        result = analyze(example)
        print(f"\nScenario: {example}")
        print(f"Prediction: {result['prediction']}")
        print(f"Reason: {result['reason']}")
        print(f"Findings: {len(result['findings'])}")
