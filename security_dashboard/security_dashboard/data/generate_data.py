"""
generate_data.py
-----------------
Creates two datasets:

1. mock_vulnerabilities.csv
   A small, realistic-looking set of "currently detected" vulnerabilities
   on a fictional system. This is what the DASHBOARD displays.
   -> Replace this later with real scanner output (Nmap/OpenVAS/Nessus/etc.)

2. training_data.csv
   A larger synthetic dataset used ONLY to train the ML risk-prediction
   model. It is not shown on the dashboard directly.

Run:
    python data/generate_data.py
"""

import numpy as np
import pandas as pd
import os

np.random.seed(42)

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

VULN_CATEGORIES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Outdated Software / Missing Patch",
    "Weak Authentication",
    "Misconfigured Server",
    "Insecure Direct Object Reference",
    "Open Port / Unnecessary Service",
    "Broken Access Control",
    "Sensitive Data Exposure",
    "Remote Code Execution",
]

SYSTEMS = [
    "Web Server (Apache)",
    "Database Server (MySQL)",
    "Login Portal",
    "File Server (FTP)",
    "API Gateway",
    "Employee Intranet",
    "Payment Gateway",
    "Admin Dashboard",
    "Email Server",
    "Cloud Storage Bucket",
]


def cvss_to_risk(cvss):
    """Standard-ish CVSS v3 severity banding, mapped to our 3-tier scale."""
    if cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    else:
        return "Low"


def make_rows(n, seed_offset=0):
    rng = np.random.default_rng(42 + seed_offset)
    rows = []
    for i in range(n):
        cvss = round(rng.uniform(1.0, 10.0), 1)
        exploit_available = rng.choice([0, 1], p=[0.55, 0.45])
        patch_available = rng.choice([0, 1], p=[0.35, 0.65])
        days_since_disclosure = int(rng.integers(1, 900))
        exposure = rng.choice(["Internal", "External"], p=[0.4, 0.6])
        category = rng.choice(VULN_CATEGORIES)

        rows.append(
            {
                "cvss_score": cvss,
                "exploit_available": exploit_available,
                "patch_available": patch_available,
                "days_since_disclosure": days_since_disclosure,
                "exposure": exposure,
                "category": category,
            }
        )
    return pd.DataFrame(rows)


def label_attack_likelihood(df):
    """
    Synthetic 'ground truth' generator for training the model.
    Combines the risk drivers into a probability, then samples a label.
    This mimics how a security analyst's intuition (CVSS + exploit
    availability + exposure + patch status + age) roughly maps to
    real-world attack likelihood.
    """
    score = (
        df["cvss_score"] / 10 * 0.45
        + df["exploit_available"] * 0.25
        + (df["exposure"] == "External").astype(int) * 0.15
        + (1 - df["patch_available"]) * 0.10
        + np.clip(df["days_since_disclosure"] / 900, 0, 1) * 0.05
    )
    score = score + np.random.default_rng(1).normal(0, 0.05, len(df))
    score = score.clip(0, 1)

    labels = pd.cut(
        score, bins=[-0.01, 0.35, 0.65, 1.01], labels=["Low", "Medium", "High"]
    )
    return score, labels


def build_mock_vulnerabilities(n=18):
    df = make_rows(n, seed_offset=99)
    df.insert(0, "vuln_id", [f"VULN-{1000+i}" for i in range(n)])
    df.insert(1, "system", np.random.default_rng(7).choice(SYSTEMS, n, replace=True))
    cve_ids = [
        f"CVE-2024-{np.random.default_rng(i).integers(1000,9999)}" for i in range(n)
    ]
    df.insert(2, "cve_id", cve_ids)
    df["risk_level"] = df["cvss_score"].apply(cvss_to_risk)
    return df


def build_training_data(n=1200):
    df = make_rows(n, seed_offset=0)
    score, labels = label_attack_likelihood(df)
    df["attack_probability"] = score
    df["attack_likelihood"] = labels
    return df


if __name__ == "__main__":
    mock_df = build_mock_vulnerabilities()
    mock_path = os.path.join(OUT_DIR, "mock_vulnerabilities.csv")
    mock_df.to_csv(mock_path, index=False)
    print(f"Wrote {len(mock_df)} rows -> {mock_path}")

    train_df = build_training_data()
    train_path = os.path.join(OUT_DIR, "training_data.csv")
    train_df.to_csv(train_path, index=False)
    print(f"Wrote {len(train_df)} rows -> {train_path}")
