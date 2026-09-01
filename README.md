# SOC Investigation Copilot

An automated Security Operations Center (SOC) investigation platform that integrates Wazuh alerts with Python, Flask, and SQLite.

## Features

- Wazuh alert ingestion
- Automated alert parsing
- SOC risk scoring
- Severity classification
- MITRE ATT&CK mapping
- Alert investigation findings
- Investigation recommendations
- SQLite-based alert storage
- Web-based SOC dashboard
- Alert search and severity filtering
- Detailed alert investigation page
- Investigation report generation
- Secure login system
- Automatic Wazuh alert monitoring

## Technologies

- Python
- Flask
- SQLite
- Wazuh
- HTML
- CSS
- JavaScript
- MITRE ATT&CK

## Project Architecture

Wazuh
↓
Wazuh Alert Logs
↓
Wazuh Reader
↓
Alert Parser
↓
Investigation Engine
↓
Risk Assessment
↓
SQLite Database
↓
Flask SOC Dashboard

## Project Workflow

1. Wazuh generates security alerts.
2. The application collects and parses the alerts.
3. Alerts are analyzed by the investigation engine.
4. Risk score and risk level are calculated.
5. MITRE ATT&CK techniques are identified.
6. Investigation findings and recommendations are generated.
7. Results are stored in SQLite.
8. SOC analysts investigate alerts through the web dashboard.
9. Investigation reports can be generated for individual alerts.

## Security Monitoring

The project supports investigation of security events such as:

- Authentication activity
- Failed login attempts
- Suspicious command execution
- Process activity
- Privilege-related activity
- File integrity events
- MITRE ATT&CK mapped events

## Author

Dharun Prasath

Cybersecurity Student | SOC Analyst Enthusiast
