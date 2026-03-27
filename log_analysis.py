
## 2) log_analysis.py

```python
import pandas as pd


def load_logs(file_path: str) -> pd.DataFrame:
    """Load log data from CSV."""
    return pd.read_csv(file_path)


def detect_high_activity(df: pd.DataFrame, threshold: int = 3) -> pd.DataFrame:
    """
    Detect users with activity counts above a threshold.
    """
    activity_counts = df.groupby("user").size().reset_index(name="activity_count")
    anomalies = activity_counts[activity_counts["activity_count"] > threshold]
    return anomalies


def detect_suspicious_actions(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flag log entries containing potentially suspicious actions.
    """
    suspicious_actions = ["delete", "download"]
    suspicious_df = df[df["action"].isin(suspicious_actions)].copy()
    return suspicious_df


def map_to_mitre(action: str) -> str:
    """
    Very simple illustrative mapping to MITRE ATT&CK-style concepts.
    This is for educational demonstration only.
    """
    mapping = {
        "login": "Valid Accounts",
        "download": "Data from Information Repositories",
        "delete": "Indicator Removal on Host",
    }
    return mapping.get(action, "Uncategorized")


def add_mitre_mapping(df: pd.DataFrame) -> pd.DataFrame:
    """Add a simple MITRE-style category column."""
    df = df.copy()
    df["mitre_mapping"] = df["action"].apply(map_to_mitre)
    return df


def main() -> None:
    print("\nLoading logs...")
    logs = load_logs("sample_logs.csv")

    print("\nFull log data:")
    print(logs)

    print("\nDetecting high-activity users...")
    anomalies = detect_high_activity(logs, threshold=3)
    print(anomalies if not anomalies.empty else "No high-activity anomalies detected.")

    print("\nDetecting suspicious actions...")
    suspicious = detect_suspicious_actions(logs)
    suspicious = add_mitre_mapping(suspicious)
    print(suspicious if not suspicious.empty else "No suspicious actions detected.")

    print("\nSummary:")
    print(f"Total log entries: {len(logs)}")
    print(f"High-activity users flagged: {len(anomalies)}")
    print(f"Suspicious actions flagged: {len(suspicious)}")


if __name__ == "__main__":
    main()
