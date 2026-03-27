"""
log_analysis.py
───────────────────────────────────────────────────────────────
Security Log Analysis & Anomaly Detection Engine
Author : Md Tariqul Islam  (github.com/mtariqi)
Purpose: Parse structured log data, detect behavioural anomalies,
         triage alerts, and surface MITRE ATT&CK mappings.
───────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Optional

import pandas as pd

# ── MITRE ATT&CK lightweight reference map ──────────────────────────────────
MITRE_MAP: dict[str, dict] = {
    "login":    {"tactic": "Initial Access",       "technique": "T1078 – Valid Accounts"},
    "download": {"tactic": "Exfiltration",         "technique": "T1048 – Exfiltration Over Alt Protocol"},
    "delete":   {"tactic": "Impact",               "technique": "T1485 – Data Destruction"},
    "escalate": {"tactic": "Privilege Escalation", "technique": "T1068 – Exploitation for Privilege Escalation"},
    "scan":     {"tactic": "Discovery",            "technique": "T1046 – Network Service Discovery"},
}

# ── Severity thresholds ───────────────────────────────────────────────────────
SEVERITY_RULES: dict[str, int] = {
    "delete":   1,   # any delete is HIGH
    "escalate": 1,
    "scan":     2,
    "download": 3,
    "login":    5,
}

SEVERITY_LABELS = {1: "🔴 CRITICAL", 2: "🟠 HIGH", 3: "🟡 MEDIUM", 4: "🔵 LOW", 5: "⚪ INFO"}


# ── Sample log generator ──────────────────────────────────────────────────────
def _build_sample_logs() -> pd.DataFrame:
    """Return a realistic sample log DataFrame."""
    rows = [
        ("A", "login",    "2024-01-01 00:00", "192.168.1.10", "success"),
        ("B", "login",    "2024-01-01 01:00", "10.0.0.5",     "success"),
        ("A", "download", "2024-01-01 02:00", "192.168.1.10", "success"),
        ("C", "login",    "2024-01-01 03:00", "172.16.0.3",   "failed"),
        ("A", "delete",   "2024-01-01 04:00", "192.168.1.10", "success"),
        ("B", "login",    "2024-01-01 05:00", "10.0.0.5",     "failed"),
        ("D", "login",    "2024-01-01 06:00", "203.0.113.9",  "success"),
        ("A", "download", "2024-01-01 07:00", "192.168.1.10", "success"),
        ("C", "login",    "2024-01-01 07:30", "172.16.0.3",   "failed"),
        ("C", "login",    "2024-01-01 07:31", "172.16.0.3",   "failed"),
        ("C", "login",    "2024-01-01 07:32", "172.16.0.3",   "failed"),
        ("D", "scan",     "2024-01-01 08:00", "203.0.113.9",  "success"),
        ("A", "escalate", "2024-01-01 09:00", "192.168.1.10", "success"),
    ]
    df = pd.DataFrame(rows, columns=["user", "action", "timestamp", "source_ip", "status"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


# ── Core analysis functions ───────────────────────────────────────────────────

def load_logs(filepath: Optional[str] = None) -> pd.DataFrame:
    """Load logs from CSV or fall back to built-in sample data."""
    if filepath:
        try:
            df = pd.read_csv(filepath, parse_dates=["timestamp"])
            print(f"[+] Loaded {len(df)} log entries from '{filepath}'")
            return df
        except FileNotFoundError:
            print(f"[!] File not found: '{filepath}'. Falling back to sample data.")
    print("[*] Using built-in sample log data.\n")
    return _build_sample_logs()


def enrich_with_mitre(df: pd.DataFrame) -> pd.DataFrame:
    """Add MITRE ATT&CK tactic and technique columns."""
    df = df.copy()
    df["mitre_tactic"]    = df["action"].map(lambda a: MITRE_MAP.get(a, {}).get("tactic",    "Unknown"))
    df["mitre_technique"] = df["action"].map(lambda a: MITRE_MAP.get(a, {}).get("technique", "Unknown"))
    return df


def compute_severity(df: pd.DataFrame) -> pd.DataFrame:
    """Assign a severity score and label to every event."""
    df = df.copy()
    df["severity_score"] = df["action"].map(lambda a: SEVERITY_RULES.get(a, 4))
    df["severity_label"] = df["severity_score"].map(SEVERITY_LABELS)
    return df


def detect_brute_force(df: pd.DataFrame,
                       window_minutes: int = 5,
                       threshold: int = 3) -> pd.DataFrame:
    """Flag users with ≥ threshold failed logins within a rolling window."""
    failed = df[(df["action"] == "login") & (df["status"] == "failed")].copy()
    if failed.empty:
        return pd.DataFrame()
    failed = failed.sort_values("timestamp")
    flagged = []
    for user, group in failed.groupby("user"):
        group = group.set_index("timestamp").sort_index()
        rolling = group.rolling(f"{window_minutes}min").size()
        if (rolling >= threshold).any():
            flagged.append({
                "user":       user,
                "alert_type": "Brute-Force / Credential Stuffing",
                "mitre":      "T1110 – Brute Force",
                "details":    f"{int(rolling.max())} failed logins in {window_minutes} min",
            })
    return pd.DataFrame(flagged)


def detect_high_activity(df: pd.DataFrame, threshold: int = 3) -> pd.DataFrame:
    """Flag users whose total event count exceeds threshold."""
    counts = df.groupby("user").size().reset_index(name="event_count")
    anomalies = counts[counts["event_count"] > threshold].copy()
    anomalies["alert_type"] = "Unusual High Activity Volume"
    anomalies["mitre"]      = "T1078 – Valid Accounts (Abuse)"
    return anomalies


def triage_alerts(alerts_df: pd.DataFrame) -> None:
    """Print a formatted triage summary."""
    if alerts_df.empty:
        print("  ✅  No anomalies detected.\n")
        return
    for _, row in alerts_df.iterrows():
        print(f"  ┌─ User      : {row.get('user', 'N/A')}")
        print(f"  │  Alert     : {row.get('alert_type', 'N/A')}")
        print(f"  │  MITRE     : {row.get('mitre', 'N/A')}")
        if "event_count" in row:
            print(f"  │  Events    : {row['event_count']}")
        if "details" in row:
            print(f"  │  Detail    : {row.get('details', '')}")
        print(f"  └─{'─' * 50}")


# ── Report printer ────────────────────────────────────────────────────────────

def print_report(df: pd.DataFrame,
                 brute_force_alerts: pd.DataFrame,
                 high_activity_alerts: pd.DataFrame) -> None:
    """Print a structured security operations report."""
    separator = "=" * 62

    print(f"\n{separator}")
    print("  SECURITY LOG ANALYSIS REPORT")
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Log Entries: {len(df)}")
    print(separator)

    # ── Activity summary ──────────────────────────────────────────
    print("\n📊  USER ACTIVITY SUMMARY")
    print("-" * 40)
    summary = (
        df.groupby(["user", "action"])
          .size()
          .unstack(fill_value=0)
    )
    print(summary.to_string())

    # ── Severity breakdown ────────────────────────────────────────
    print("\n\n🔍  EVENT SEVERITY BREAKDOWN")
    print("-" * 40)
    severity_counts = df["severity_label"].value_counts()
    for label, count in severity_counts.items():
        bar = "█" * count
        print(f"  {label:<20} {bar} ({count})")

    # ── MITRE ATT&CK coverage ─────────────────────────────────────
    print("\n\n🗺️   MITRE ATT&CK EVENT COVERAGE")
    print("-" * 40)
    mitre_summary = df.groupby(["mitre_tactic", "mitre_technique"]).size().reset_index(name="count")
    for _, row in mitre_summary.iterrows():
        print(f"  [{row['count']:>2}x]  {row['mitre_tactic']:<26} {row['mitre_technique']}")

    # ── Anomaly triage ────────────────────────────────────────────
    print(f"\n\n🚨  ANOMALY DETECTION — HIGH ACTIVITY (threshold > 3)")
    print("-" * 40)
    triage_alerts(high_activity_alerts)

    print(f"\n🚨  ANOMALY DETECTION — BRUTE-FORCE (≥3 failures / 5 min)")
    print("-" * 40)
    triage_alerts(brute_force_alerts)

    print(f"\n{separator}")
    print("  END OF REPORT")
    print(f"{separator}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def main(log_file: Optional[str] = None) -> None:
    df = load_logs(log_file)
    df = enrich_with_mitre(df)
    df = compute_severity(df)

    brute_force_alerts   = detect_brute_force(df)
    high_activity_alerts = detect_high_activity(df, threshold=3)

    print_report(df, brute_force_alerts, high_activity_alerts)


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else None
    main(log_path)
