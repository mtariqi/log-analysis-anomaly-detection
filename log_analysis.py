import pandas as pd

# Sample log data (simulate logs)
data = {
    "user": ["A", "B", "A", "C", "A", "B", "D", "A"],
    "action": ["login", "login", "download", "login", "delete", "login", "login", "download"],
    "timestamp": pd.date_range(start="2024-01-01", periods=8, freq="H")
}

df = pd.DataFrame(data)

# Count actions per user
activity_count = df.groupby("user").size()

# Detect anomalies (simple threshold)
threshold = 3
anomalies = activity_count[activity_count > threshold]

print("User Activity Counts:\n", activity_count)
print("\n🚨 Potential Anomalies:\n", anomalies)
