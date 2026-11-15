
import re

# AI Red Team Cyber Range
# Version 7 - Concept-based security classification

CATEGORIES = (
    "broken_access_control",
    "sql_injection",
    "insecure_configuration",
)

CONCEPTS = {
    "access": {
        "identity": [
            r"\buser\b", r"\baccount\b", r"\bemployee\b",
            r"\bcustomer\b", r"\bvisitor\b", r"\bguest\b",
            r"\bsubscriber\b", r"\bcaller\b", r"\bsession\b",
            r"\battacker\b",
        ],
        "resource": [
            r"\brecords?\b", r"\bdocuments?\b", r"\bfiles?\b",
            r"\binvoices?\b", r"\bprofiles?\b", r"\bpayroll\b",
            r"\bcontracts?\b", r"\bmessages?\b",
            r"\bpayment methods?\b", r"\baccount information\b",
            r"\badministrative function\b",
        ],
        "unauthorized": [
            r"\bwithout (?:authorization|permission|authentication)\b",
            r"\bwithout being authenticated\b",
            r"\bno active session\b",
            r"\bunauthenticated\b",
            r"\blacking the required role\b",
            r"\breserved for (?:system )?administrators\b",
            r"\bshould require elevated privileges\b",
            r"\bother people's\b",
            r"\banother (?:household|subscriber|customer|user|tenant)\b",
            r"\bstranger's\b",
            r"\bseparate team\b",
            r"\bcompeting company\b",
            r"\bprivate\b",
            r"\brestricted\b",
        ],
        "action": [
            r"\baccess(?:es|ed)?\b", r"\bopens?\b",
            r"\bretriev(?:es|ed|e)\b", r"\bdownloads?\b",
            r"\breads?\b", r"\bviews?\b",
            r"\bdeletes?\b", r"\bmodif(?:y|ies|ied)\b",
            r"\binvokes?\b", r"\bexecutes?\b",
            r"\breceives?\b", r"\bgains? access\b",
            r"\breturns?\b",
        ],
    },

    "sql": {
        "input": [
            r"\binput\b", r"\bparameter\b", r"\brequest\b",
            r"\bsearch\b", r"\bfilter\b", r"\bform\b",
            r"\busername\b", r"\bcustomer name\b",
            r"\bquery.string\b", r"\burl\b",
            r"\bunchecked text\b", r"\braw request values\b",
        ],
        "database": [
            r"\bsql\b", r"\bdatabase\b", r"\bquery\b",
            r"\bselect\b", r"\bwhere\b",
            r"\bpredicate\b", r"\bsubquery\b",
            r"\bbackend\b",
        ],
        "manipulation": [
            r"\binject(?:s|ed|ion)?\b",
            r"\bconcatenat(?:es|ed|ing)\b",
            r"\binterpolat(?:es|ed|ing)\b",
            r"\bdynamically assembled\b",
            r"\bunsanitized\b",
            r"\bwithout using bound parameters\b",
            r"\bwithout parameter binding\b",
            r"\bterminate a string literal\b",
            r"\balter(?:s|ed)?\b",
            r"\bchanges? (?:the )?query\b",
            r"\battacker.supplied\b",
            r"\bquote.and.comment\b",
            r"\bcrafted\b",
        ],
        "effect": [
            r"\bbypass(?:es|ed)?\b",
            r"\breveals?\b",
            r"\bunintended\b",
            r"\bunauthorized\b",
            r"\bchanges? which rows\b",
            r"\bhidden entries\b",
            r"\bconfidential customer rows\b",
            r"\bexecute(?:s|d)?\b",
            r"\bchanges? the query result\b",
        ],
    },

    "configuration": {
        "sensitive": [
            r"\bproduction\b", r"\bserver\b",
            r"\bcloud\b", r"\bstorage\b",
            r"\badministrat(?:ive|ion)\b",
            r"\bmanagement\b", r"\bcontrol panel\b",
            r"\bdashboard\b", r"\bdiagnostic\b",
            r"\bstatus page\b", r"\bfirewall\b",
            r"\bservice\b", r"\bwebsite\b",
            r"\bappliance\b",
        ],
        "exposure": [
            r"\bpublic(?:ly)?\b",
            r"\binternet\b", r"\bworldwide\b",
            r"\banyone\b", r"\beveryone\b",
            r"\banonymous\b", r"\boutsiders\b",
            r"\boutside the corporate network\b",
            r"\bunrestricted\b",
            r"\bexpos(?:es|ed|ing)\b",
            r"\baccessible\b",
            r"\breachable\b",
        ],
        "weakness": [
            r"\bno authentication\b",
            r"\bwithout authentication\b",
            r"\bblank password\b",
            r"\bvendor.supplied password\b",
            r"\binitial login\b",
            r"\bdefault credentials\b",
            r"\bno network restrictions\b",
            r"\bturned off\b",
            r"\bdisabled\b",
            r"\bmisconfigured\b",
            r"\bconfiguration secrets\b",
            r"\bdebug\b",
            r"\bexception details\b",
            r"\bfile paths\b",
            r"\btroubleshooting interface\b",
            r"\bunrestricted inbound\b",
        ],
    },
}

# Strong evidence that a description concerns an actual
# vulnerability rather than simply mentioning security terms.
STRONG_RULES = {
    "broken_access_control": [
        r"\bwithout being authenticated\b",
        r"\blacking the required role\b",
        r"\bshould require elevated privileges\b",
        r"\bother people's\b",
        r"\bstranger's\b",
        r"\banother subscriber's\b",
        r"\breserved for system administrators\b",
    ],
    "sql_injection": [
        r"\bsql injection\b",
        r"\binjected subquery\b",
        r"\bunsanitized input\b",
        r"\bwithout using bound parameters\b",
        r"\bwithout parameter binding\b",
        r"\bquote.and.comment sequence\b",
        r"\bdynamically assembled sql\b",
    ],
    "insecure_configuration": [
        r"\bblank password\b",
        r"\bvendor.supplied password\b",
        r"\bworldwide access\b",
        r"\bno authentication requirement\b",
        r"\bconfiguration secrets\b",
        r"\bfirewall rule allows unrestricted\b",
        r"\bauthentication checks are turned off\b",
    ],
}

# Successful security controls and authorized exercises.
SAFE_CONTEXT = [
    r"\bapproved exercise\b",
    r"\bisolated.*training\b",
    r"\bnonproduction training\b",
    r"\bown authenticated account\b",
    r"\bnormal duties\b",
    r"\bparameterized queries\b",
    r"\bprevent attacker input\b",
    r"\breturns? a 403\b",
    r"\bfailed attempt\b",
    r"\bno public access\b",
    r"\bonly through the corporate vpn\b",
    r"\bbefore installation\b",
    r"\bbefore releasing\b",
    r"\bdeliberately public\b",
    r"\bwithout applying it\b",
    r"\bwrites? documentation\b",
    r"\brotates? default credentials\b",
    r"\breplaces? a vendor password\b",
]

def normalize(description):
    text = str(description).lower()
    text = re.sub(r"[^a-z0-9\s'-]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def matches(text, patterns):
    return [
        pattern for pattern in patterns
        if re.search(pattern, text, flags=re.IGNORECASE)
    ]


def concept_matches(text, category, concept):
    return matches(text, CONCEPTS[category][concept])


def analyze(description):
    text = normalize(description)

    if not text:
        return {
            "prediction": "unknown",
            "reason": "Empty description.",
            "findings": [],
        }

    safe = matches(text, SAFE_CONTEXT)

    # Explicit safe context takes precedence.
    # Mixed vulnerability/remediation descriptions may
    # still need manual review.
    if safe:
        return {
            "prediction": "unknown",
            "reason": "Authorized or defensive context detected.",
            "findings": [],
            "safe_evidence": safe,
        }

    scores = {}
    findings = []

    # Access control: identity + resource + unauthorized
    # context + access action.
    access = {
        name: concept_matches(text, "access", name)
        for name in CONCEPTS["access"]
    }

    access_score = (
        2 * bool(access["identity"])
        + 2 * bool(access["resource"])
        + 4 * bool(access["unauthorized"])
        + 2 * bool(access["action"])
        + 3 * bool(matches(text, STRONG_RULES["broken_access_control"]))
    )

    if access["unauthorized"] and access["action"]:
        scores["broken_access_control"] = access_score

    # SQL injection: database context, attacker-controlled
    # input, manipulation, and/or resulting impact.
    sql = {
        name: concept_matches(text, "sql", name)
        for name in CONCEPTS["sql"]
    }

    sql_score = (
        2 * bool(sql["input"])
        + 3 * bool(sql["database"])
        + 4 * bool(sql["manipulation"])
        + 2 * bool(sql["effect"])
        + 4 * bool(matches(text, STRONG_RULES["sql_injection"]))
    )

    if sql["database"] and sql["manipulation"]:
        scores["sql_injection"] = sql_score

    # Insecure configuration: sensitive service or system
    # plus public exposure or an unsafe setting.
    config = {
        name: concept_matches(text, "configuration", name)
        for name in CONCEPTS["configuration"]
    }

    config_score = (
        2 * bool(config["sensitive"])
        + 3 * bool(config["exposure"])
        + 4 * bool(config["weakness"])
        + 4 * bool(matches(text, STRONG_RULES["insecure_configuration"]))
    )

    if config["sensitive"] and config["exposure"] and config["weakness"]:
        scores["insecure_configuration"] = config_score
    elif matches(text, STRONG_RULES["insecure_configuration"]):
        scores["insecure_configuration"] = config_score

    if not scores:
        return {
            "prediction": "unknown",
            "reason": "Insufficient contextual evidence.",
            "findings": [],
        }

    for category, score in scores.items():
        findings.append({
            "category": category,
            "score": score,
        })

    findings.sort(
        key=lambda item: (
            -item["score"],
            CATEGORIES.index(item["category"])
        )
    )

    return {
        "prediction": findings[0]["category"],
        "reason": "Highest contextual evidence score.",
        "findings": findings,
    }


def predict(description):
    return analyze(description)["prediction"]


if __name__ == "__main__":
    examples = [
        "A guest invokes an administrative function despite lacking the required role.",
        "A web form passes unsanitized input into dynamically assembled SQL.",
        "A cloud storage share permits worldwide access to confidential backups.",
        "A tester submits a UNION SELECT string during an approved exercise.",
        "A firewall rule allows unrestricted inbound connections to a sensitive management port.",
    ]

    print("=" * 55)
    print("AI RED TEAM - CLASSIFIER VERSION 7")
    print("=" * 55)

    for example in examples:
        result = analyze(example)
        print(f"\nScenario: {example}")
        print(f"Prediction: {result['prediction']}")
        print(f"Reason: {result['reason']}")
