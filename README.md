# 🛡️ SOC Investigation Copilot

An automated Security Operations Center (SOC) investigation platform that integrates Wazuh alerts with Python, Flask, and SQLite.

The system collects security alerts from Wazuh, parses and analyzes them, calculates risk scores, maps events to MITRE ATT&CK techniques, and provides a web-based dashboard for SOC investigation.

---

## 🚀 Features

- Wazuh alert ingestion
- Automated alert parsing
- SOC risk scoring
- Severity classification
- MITRE ATT&CK mapping
- Automated investigation findings
- Investigation recommendations
- SQLite-based alert storage
- Web-based SOC dashboard
- Alert search and severity filtering
- Detailed alert investigation
- Incident report generation
- Secure login system
- Automatic Wazuh alert monitoring

---

## 🧰 Technologies Used

- **Python**
- **Flask**
- **SQLite**
- **Wazuh**
- **HTML**
- **CSS**
- **JavaScript**
- **MITRE ATT&CK**
- **PowerShell**
- **SSH**

---

## 🏗️ Project Architecture

```text
                    ┌─────────────────┐
                    │      Wazuh      │
                    │ Security Alerts │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Wazuh Reader   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Alert Parser   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Investigation   │
                    │     Engine      │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
             ┌─────────────┐   ┌──────────────┐
             │ Risk Score  │   │ MITRE ATT&CK │
             │ & Severity  │   │    Mapping   │
             └──────┬──────┘   └──────┬───────┘
                    │                 │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │ SQLite Database │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Flask Web       │
                    │ SOC Dashboard   │
                    └─────────────────┘
