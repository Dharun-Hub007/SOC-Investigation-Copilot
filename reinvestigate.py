from app.services.wazuh_reader import WazuhReader
from app.services.investigation import InvestigationEngine
import sqlite3
import json


DATABASE = "data/soc.db"
ALERT_FILE = "alerts.json"


def update_alert(
    cursor,
    alert_id,
    investigation
):
    findings = json.dumps(
        investigation.get("findings", [])
    )

    recommendations = json.dumps(
        investigation.get("recommendations", [])
    )

    cursor.execute(
        """
        UPDATE alerts

        SET
            risk_score = ?,
            risk_level = ?,
            findings = ?,
            recommendations = ?

        WHERE alert_id = ?
        """,
        (
            investigation["risk_score"],
            investigation["risk_level"],
            findings,
            recommendations,
            alert_id
        )
    )


def main():

    print("=" * 65)
    print("       SOC INVESTIGATION COPILOT")
    print("       RE-INVESTIGATION ENGINE")
    print("=" * 65)

    print()
    print("[+] Reading Wazuh alerts...")

    reader = WazuhReader(ALERT_FILE)

    alerts = reader.read_alerts()

    print(
        f"[+] Wazuh alerts found: {len(alerts)}"
    )

    print()

    engine = InvestigationEngine()

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    updated = 0
    not_found = 0
    failed = 0

    print("[+] Re-investigating existing alerts...")
    print()

    for raw_alert in alerts:

        try:

            alert_id = raw_alert.get(
                "id",
                ""
            )

            if not alert_id:
                failed += 1
                continue

            # Check whether alert exists
            cursor.execute(
                """
                SELECT id
                FROM alerts
                WHERE alert_id = ?
                LIMIT 1
                """,
                (alert_id,)
            )

            result = cursor.fetchone()

            if result is None:

                not_found += 1
                continue

            # Parse alert
            parsed_alert = reader.parse_alert(
                raw_alert
            )

            # Run new investigation
            investigation = engine.investigate(
                parsed_alert
            )

            # Update database
            update_alert(
                cursor,
                alert_id,
                investigation
            )

            updated += 1

            if updated <= 10:

                print(
                    f"[+] Updated | "
                    f"ID: {alert_id} | "
                    f"Rule: {parsed_alert['rule']['id']} | "
                    f"Risk: "
                    f"{investigation['risk_score']} "
                    f"{investigation['risk_level']}"
                )

        except Exception as error:

            failed += 1

            print(
                f"[!] Failed | "
                f"{raw_alert.get('id', 'unknown')} | "
                f"{error}"
            )

    connection.commit()

    connection.close()

    print()
    print("=" * 65)
    print("RE-INVESTIGATION COMPLETE")
    print("=" * 65)

    print(
        f"Total Wazuh alerts : {len(alerts)}"
    )

    print(
        f"Database updated   : {updated}"
    )

    print(
        f"Not found in DB    : {not_found}"
    )

    print(
        f"Failed             : {failed}"
    )

    print("=" * 65)


if __name__ == "__main__":
    main()