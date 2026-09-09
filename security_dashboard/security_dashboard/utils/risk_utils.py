"""
risk_utils.py
-------------
Small shared helpers: colors for risk levels, and the glossary text
shown in the "Understanding This Dashboard" panel.
"""

RISK_COLORS = {
    "Low": "#2ecc71",     # green
    "Medium": "#f1c40f",  # amber
    "High": "#e74c3c",    # red
}

RISK_BADGE_CLASS = {
    "Low": "success",
    "Medium": "warning",
    "High": "danger",
}

GLOSSARY = [
    (
        "CVSS Score",
        "Common Vulnerability Scoring System. An industry-standard score from "
        "0-10 rating how severe a vulnerability is. 0-3.9 = Low, 4.0-6.9 = "
        "Medium, 7.0-10 = High severity.",
    ),
    (
        "CVE ID",
        "Common Vulnerabilities and Exposures identifier. A unique public "
        "reference number (e.g. CVE-2024-1234) assigned to a specific, "
        "known vulnerability so it can be tracked across tools and reports.",
    ),
    (
        "Exploit Available",
        "Whether a working piece of code or technique that attackers can use "
        "to actually take advantage of the vulnerability is known to exist "
        "'in the wild' or in public exploit databases.",
    ),
    (
        "Patch Available",
        "Whether the vendor/developer has released an official fix (update, "
        "hotfix, or configuration change) that closes the vulnerability.",
    ),
    (
        "Exposure",
        "Whether the vulnerable system is reachable only from inside the "
        "organization's network (Internal) or from the public internet "
        "(External). External exposure is generally riskier.",
    ),
    (
        "Risk Level",
        "A simplified Low / Medium / High rating derived from the CVSS score, "
        "used to help prioritize which issues to fix first.",
    ),
    (
        "Attack Likelihood (Predicted)",
        "An estimate, produced by a machine learning model, of how likely a "
        "given vulnerability is to actually be exploited in an attack -- "
        "based on patterns learned from severity, exploit availability, "
        "exposure, patch status, and vulnerability age.",
    ),
    (
        "Attack Probability",
        "The raw numeric confidence (0-1) behind the model's Attack "
        "Likelihood prediction. Closer to 1 means the model is more "
        "confident this vulnerability resembles historically exploited "
        "cases.",
    ),
    (
        "SQL Injection",
        "An attack where malicious database commands are inserted into an "
        "input field, tricking the application into running unintended "
        "queries against its database.",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "An attack where malicious scripts are injected into a trusted "
        "website and run in other users' browsers, often to steal session "
        "data or impersonate users.",
    ),
    (
        "Remote Code Execution (RCE)",
        "A critical class of vulnerability that lets an attacker run "
        "arbitrary code on a target system remotely, often leading to full "
        "system compromise.",
    ),
    (
        "Broken Access Control",
        "A flaw where the system fails to properly restrict what "
        "authenticated users are allowed to see or do, letting them access "
        "data or actions they shouldn't have permission for.",
    ),
]


def risk_badge_color(level: str) -> str:
    return RISK_COLORS.get(level, "#95a5a6")
