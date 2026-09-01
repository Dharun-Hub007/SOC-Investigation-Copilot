from app.services.wazuh_reader import WazuhReader
from app.services.investigation import InvestigationEngine
from app.services.database import AlertDatabase


def main():

    print("=" * 60)
    print("       SOC INVESTIGATION COPILOT")
    print("       AUTOMATIC WAZUH INGESTION")
    print("=" * 60)

    print()
    print("[+] Reading Wazuh alerts...")

    reader = WazuhReader("alerts.json")
    alerts = reader.read_alerts()

    print(f"[+] Total alerts found: {len(alerts)}")
    print()

    database = AlertDatabase()
    engine = InvestigationEngine()

    new_alerts = 0
    duplicates = 0
    failed = 0

    for raw_alert in alerts:

        try:
            # Get Wazuh alert ID
            alert_id = raw_alert.get("id", "")

            if not alert_id:
                failed += 1
                continue

            # Check duplicate
            if database.alert_exists(alert_id):
                duplicates += 1
                continue

            # Parse Wazuh alert
            parsed_alert = reader.parse_alert(raw_alert)

            # Investigate alert
            investigation = engine.investigate(parsed_alert)

            # Save alert
            database.save_alert(
                parsed_alert,
                investigation
            )

            new_alerts += 1

            print(
                f"[+] New alert saved: "
                f"{alert_id} | "
                f"Rule: {parsed_alert['rule']['id']} | "
                f"Risk: {investigation['risk_score']} "
                f"{investigation['risk_level']}"
            )

        except Exception as error:

            failed += 1

            print(
                f"[!] Failed to process alert: "
                f"{raw_alert.get('id', 'unknown')} | "
                f"{error}"
            )

    print()
    print("=" * 60)
    print("INGESTION COMPLETE")
    print("=" * 60)

    print(f"Total alerts found : {len(alerts)}")
    print(f"New alerts saved   : {new_alerts}")
    print(f"Duplicates skipped : {duplicates}")
    print(f"Failed alerts      : {failed}")

    print("=" * 60)


if __name__ == "__main__":
    main()