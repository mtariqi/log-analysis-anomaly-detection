<div align="center">

```
██╗      ██████╗  ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗
██║     ██╔═══██╗██╔════╝     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
██║     ██║   ██║██║  ███╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗
██║     ██║   ██║██║   ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║
███████╗╚██████╔╝╚██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║
╚══════╝ ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝
```

### 🛡️ Security Log Analysis & Anomaly Detection Engine

*Parse → Enrich → Detect → Triage → Respond*

---
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19264645.svg)](https://doi.org/10.5281/zenodo.19264645)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Pandas](https://img.shields.io/badge/Pandas-2.x-150458?style=for-the-badge&logo=pandas&logoColor=white)](https://pandas.pydata.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-E8000B?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsOSA1IDktNVY3bC05IDV6Ii8+PC9zdmc+)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Focus-SecOps%20%2F%20Blue%20Team-0EA5E9?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/mtariqi)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)](https://github.com/mtariqi)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-FF6B6B?style=for-the-badge)](https://github.com/mtariqi/log-analysis-anomaly-detection/pulls)

</div>

---

## Why This Project

Security operations teams face a relentless flood of alerts — most of them noisy, redundant, or low-fidelity. Effective detection isn't just about generating alerts; it's about generating the *right* alerts with enough context to act on them immediately.

This project demonstrates how lightweight Python automation can:

- **Parse and normalize** structured log data at scale
- **Detect anomalous patterns** using threshold and behavioral heuristics
- **Enrich every event** with MITRE ATT&CK tactic and technique context
- **Triage alerts** with severity scoring to reduce analyst fatigue
- **Support consistent investigation workflows** without heavyweight SIEM infrastructure

> *Built to reflect real-world Blue Team thinking: signal over noise, context over volume.*

---

## ✨ Features

| Feature | Description |
|---|---|
| 📥 **Log Ingestion** | Load from CSV or use built-in sample data for instant demo |
| 🗺️ **MITRE ATT&CK Enrichment** | Automatically maps actions to tactics & techniques (T1078, T1110, T1485…) |
| 🔴 **Severity Scoring** | CRITICAL → HIGH → MEDIUM → LOW → INFO classification per event |
| 🧠 **Brute-Force Detection** | Rolling-window analysis flags credential stuffing within configurable time bounds |
| 📊 **Behavioural Anomaly Detection** | Identifies users with abnormally high event volumes |
| 🚨 **Alert Triage Output** | Structured, human-readable triage summaries for each flagged entity |
| 📈 **Activity Summary** | Per-user, per-action pivot breakdown |
| 🔌 **Extensible Design** | Modular functions — plug in your own detection logic or data sources |

---

## 🗂️ Project Structure

```text
log-analysis-anomaly-detection/
│
├── 📄 README.md               ← You are here
├── 🐍 log_analysis.py         ← Core analysis engine
├── 📊 sample_logs.csv         ← Example log dataset (CSV format)
├── 📦 requirements.txt        ← Python dependencies
├── 🚫 .gitignore              ← Standard Python ignores
└── ⚖️  LICENSE                ← MIT License
```

---

## ⚙️ Tech Stack

<div align="center">

| Layer | Technology |
|---|---|
| Language | Python 3.9+ |
| Data Processing | pandas |
| Threat Intel | MITRE ATT&CK Framework |
| Detection Logic | Threshold + Rolling-window heuristics |
| Output | CLI structured report |

</div>

---

## 🚀 Getting Started

### Prerequisites

```bash
python --version   # Requires Python 3.9+
```

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/mtariqi/log-analysis-anomaly-detection.git
cd log-analysis-anomaly-detection

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run with built-in sample data
python log_analysis.py

# 4. Or point it at your own CSV log file
python log_analysis.py path/to/your/logs.csv
```

### Expected CSV Format

```csv
user,action,timestamp,source_ip,status
alice,login,2024-01-01 08:00:00,192.168.1.5,success
bob,download,2024-01-01 08:05:00,10.0.0.2,success
carol,login,2024-01-01 08:06:00,203.0.113.1,failed
```

---

## 📋 Sample Output

```
══════════════════════════════════════════════════════════════
  SECURITY LOG ANALYSIS REPORT
  Generated : 2024-01-01 09:00:00
  Log Entries: 13
══════════════════════════════════════════════════════════════

📊  USER ACTIVITY SUMMARY
────────────────────────────────────────
action   delete  download  escalate  login  scan
user
A             1         2         1      1     0
B             0         0         0      2     0
C             0         0         0      3     0
D             0         0         0      1     1

🔍  EVENT SEVERITY BREAKDOWN
────────────────────────────────────────
  🔴 CRITICAL           ██ (2)
  🟠 HIGH               █ (1)
  🟡 MEDIUM             ████ (4)
  ⚪ INFO               ██████ (6)

🗺️   MITRE ATT&CK EVENT COVERAGE
────────────────────────────────────────
  [ 2x]  Exfiltration         T1048 – Exfiltration Over Alt Protocol
  [ 1x]  Impact               T1485 – Data Destruction
  [ 1x]  Privilege Escalation T1068 – Exploitation for Privilege Escalation
  [ 7x]  Initial Access       T1078 – Valid Accounts
  [ 1x]  Discovery            T1046 – Network Service Discovery

🚨  ANOMALY DETECTION — HIGH ACTIVITY (threshold > 3)
────────────────────────────────────────
  ┌─ User      : A
  │  Alert     : Unusual High Activity Volume
  │  MITRE     : T1078 – Valid Accounts (Abuse)
  │  Events    : 5
  └───────────────────────────────────────────────────

🚨  ANOMALY DETECTION — BRUTE-FORCE (≥3 failures / 5 min)
────────────────────────────────────────
  ┌─ User      : C
  │  Alert     : Brute-Force / Credential Stuffing
  │  MITRE     : T1110 – Brute Force
  │  Detail    : 3 failed logins in 5 min
  └───────────────────────────────────────────────────
```

---

## 🗺️ MITRE ATT&CK Coverage

| Action | Tactic | Technique |
|---|---|---|
| `login` | Initial Access | T1078 – Valid Accounts |
| `download` | Exfiltration | T1048 – Exfiltration Over Alt Protocol |
| `delete` | Impact | T1485 – Data Destruction |
| `escalate` | Privilege Escalation | T1068 – Exploitation for Privilege Escalation |
| `scan` | Discovery | T1046 – Network Service Discovery |

---

## 💡 Example Use Cases

- **Insider Threat Detection** — Identify employees with unusual access patterns or destructive actions
- **Credential Attack Triage** — Surface brute-force and credential stuffing attempts automatically
- **Alert Fatigue Reduction** — Severity scoring ensures analysts focus on what matters
- **SIEM Supplement** — Run alongside existing tooling to validate detection coverage
- **SOC Training Lab** — Use sample data to practice triage and investigation workflows

---

## 📈 Learning Outcomes

- Applied **threshold and rolling-window anomaly detection** to log data
- Mapped security events to the **MITRE ATT&CK framework** for structured threat context
- Understood the analyst workflow: ingest → enrich → detect → triage → respond
- Explored how **automation reduces alert fatigue** in high-volume environments
- Practiced modular Python design for extensible security tooling

---

## 🔮 Future Improvements

- [ ] **ML-based anomaly detection** — isolation forest or autoencoder for behavioral baselining
- [ ] **Real-time streaming** — Kafka or file-tail integration for live log analysis
- [ ] **Alert dashboard** — Streamlit or Grafana visualization layer
- [ ] **Sigma rule export** — Generate detection rules from flagged patterns
- [ ] **SIEM integration** — Splunk / Elastic / Chronicle output connectors
- [ ] **IP reputation enrichment** — VirusTotal / AbuseIPDB API lookups on source IPs

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/add-ml-detection`)
3. Commit your changes (`git commit -m 'Add isolation forest detection'`)
4. Push to the branch (`git push origin feature/add-ml-detection`)
5. Open a Pull Request

---

## 👤 Author

<div align="center">

**Md Tariqul Islam**

[![GitHub](https://img.shields.io/badge/GitHub-mtariqi-181717?style=for-the-badge&logo=github)](https://github.com/mtariqi)

*Security Operations | Python Automation | Blue Team*

</div>

---

<div align="center">

*Built with intent. Deployed with purpose.*

⭐ Star this repo if it helped you — it supports continued open-source security work.

</div>
