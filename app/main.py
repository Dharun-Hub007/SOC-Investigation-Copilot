import json
import os
from datetime import datetime

from app.services.alert_parser import WazuhAlertParser
from app.services.investigator import InvestigationEngine
from app.services.report_generator import SecurityReportGenerator
from app.services.database import AlertDatabase


def load_alert(file_path):
    """Load a Wazuh alert from JSON."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def investigate_alert(file_path):
    """Parse and investigate a Wazuh alert."""

    alert = load_alert(file_path)

    # Parse Wazuh alert
    parser = WazuhAlertParser(alert)
    parsed_alert = parser.parse()

    # Investigate alert
    engine = InvestigationEngine()
    investigation = engine.investigate(parsed_alert)

    return parsed_alert, investigation


def main():

    print("=" * 60)
    print("        SOC INVESTIGATION COPILOT")
    print("=" * 60)

    print("Status     : Running")

    print(
        f"Started at : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print()

    print("Modules:")
    print("[+] Wazuh Alert Analysis       : Ready")
    print("[+] Alert Parser               : Ready")
    print("[+] Investigation Engine       : Ready")
    print("[+] Security Report Generator  : Ready")
    print("[+] Alert Database             : Ready")

    print()

    file_path = "data/sample_alert.json"

    try:

        # ==========================================================
        # 1. PARSE AND INVESTIGATE ALERT
        # ==========================================================

        parsed_alert, investigation = investigate_alert(file_path)

        print("ALERT ANALYSIS")
        print("-" * 60)

        print(f"Alert ID     : {parsed_alert['alert_id']}")
        print(f"Agent        : {parsed_alert['agent']['name']}")
        print(f"Agent IP     : {parsed_alert['agent']['ip']}")

        print()

        # ==========================================================
        # 2. RISK ASSESSMENT
        # ==========================================================

        print("RISK ASSESSMENT")
        print("-" * 60)

        print(
            f"Risk Score   : "
            f"{investigation['risk_score']}/100"
        )

        print(
            f"Risk Level   : "
            f"{investigation['risk_level']}"
        )

        print()

        # ==========================================================
        # 3. FINDINGS
        # ==========================================================

        print("FINDINGS")
        print("-" * 60)

        for finding in investigation["findings"]:
            print(f"[!] {finding}")

        print()

        # ==========================================================
        # 4. RECOMMENDATIONS
        # ==========================================================

        print("RECOMMENDATIONS")
        print("-" * 60)

        for recommendation in investigation["recommendations"]:
            print(f"[+] {recommendation}")

        print()

        # ==========================================================
        # 5. SAVE ALERT TO DATABASE
        # ==========================================================

        database = AlertDatabase()

        database.save_alert(
            parsed_alert,
            investigation
        )

        print("[+] Alert saved to SOC database.")

        print()

        # ==========================================================
        # 6. GENERATE SECURITY REPORT
        # ==========================================================

        report_generator = SecurityReportGenerator()

        report = report_generator.generate_report(
            parsed_alert,
            investigation
        )

        print(report)

        # ==========================================================
        # 7. SAVE REPORT TO FILE
        # ==========================================================

        os.makedirs("reports", exist_ok=True)

        report_file = os.path.join(
            "reports",
            f"{parsed_alert['alert_id']}_report.txt"
        )

        with open(
            report_file,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(report)

        print()
        print(f"[+] Report saved to: {report_file}")

    except Exception as error:

        print()
        print("[ERROR] Investigation failed.")
        print(f"Reason : {error}")

    print("=" * 60)


if __name__ == "__main__":
    main()