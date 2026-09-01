import json

from app.services.alert_parser import WazuhAlertParser
from app.services.investigator import InvestigationEngine


with open("data/sample_alert.json", "r", encoding="utf-8") as file:
    alert = json.load(file)


parser = WazuhAlertParser(alert)
result = parser.parse()


print()
print("=" * 60)
print("             SOC ALERT INVESTIGATION")
print("=" * 60)

print(f"Alert ID      : {result['alert_id']}")
print(f"Agent         : {result['agent']['name']}")
print(f"Agent IP      : {result['agent']['ip']}")

print()
print("RULE")
print("-" * 60)
print(f"Rule ID       : {result['rule']['id']}")
print(f"Description   : {result['rule']['description']}")
print(f"Wazuh Level   : {result['rule']['level']}")
print(f"SOC Severity  : {result['severity']}")

print()
print("MITRE ATT&CK")
print("-" * 60)
print(f"Technique     : {result['mitre']['id']}")
print(f"Tactic        : {result['mitre']['tactic']}")
print(f"Technique Name: {result['mitre']['technique']}")

print()
print("PROCESS")
print("-" * 60)
print(f"Process       : {result['process']['image']}")
print(f"Parent        : {result['process']['parent_image']}")
print(f"User          : {result['process']['user']}")
print(f"Integrity     : {result['process']['integrity_level']}")

print()
print("INVESTIGATION FLAGS")
print("-" * 60)

if result["investigation_flags"]:
    for flag in result["investigation_flags"]:
        print(f"[!] {flag}")
else:
    print("[+] No investigation flags detected.")

print()
print("=" * 60)
print("\n")
print("=" * 60)
print("              RISK & INVESTIGATION")
print("=" * 60)


engine = InvestigationEngine()

investigation = engine.investigate(result)

print(f"Risk Score    : {investigation['risk_score']}/100")
print(f"Risk Level    : {investigation['risk_level']}")

print("\nFINDINGS")

print("-" * 60)

for finding in investigation["findings"]:

    print(f"[!] {finding}")

print("\nRECOMMENDATIONS")

print("-" * 60)

for recommendation in investigation["recommendations"]:

    print(f"[+] {recommendation}")

print("=" * 60)