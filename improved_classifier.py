
import re


# Version 2: Explainable, rule-based vulnerability classifier
# Uses multiple indicators instead of one exact keyword.

def contains_any(text, phrases):
    return any(phrase in text for phrase in phrases)


def predict(description):
    text = description.lower()
    text = re.sub(r"\s+", " ", text).strip()

    # Broken access control
    access_indicators = [
        "another user's",
        "coworker's",
        "different account",
        "someone else's",
        "other user's",
        "other account",
        "unauthorized access",
        "without permission",
        "changing a record id",
        "belonging to a different"
    ]

    if contains_any(text, access_indicators):
        return "broken_access_control"

    # SQL injection
    database_indicators = [
        "sql",
        "database query",
        "database statement",
        "query manipulation",
        "database command",
        "database injection"
    ]

    injection_indicators = [
        "crafted input",
        "user-controlled",
        "unsanitized",
        "manipulates",
        "alter the structure",
        "injection"
    ]

    if (
        contains_any(text, database_indicators)
        and contains_any(text, injection_indicators)
    ):
        return "sql_injection"

    # Insecure configuration
    configuration_indicators = [
        "debug mode",
        "detailed error traces",
        "internal settings",
        "configuration details",
        "default credentials",
        "directory listing",
        "exposes sensitive configuration"
    ]

    if contains_any(text, configuration_indicators):
        return "insecure_configuration"

    return "unknown"


if __name__ == "__main__":
    examples = [
        "An employee retrieves a coworker's confidential records.",
        "An attacker manipulates a database query using crafted input.",
        "A production server reveals detailed error traces.",
        "A user successfully resets their own password."
    ]

    print("AI RED TEAM - IMPROVED CLASSIFIER V2")
    print("=" * 45)

    for example in examples:
        print(f"Description: {example}")
        print(f"Prediction: {predict(example)}")
        print("-" * 45)
