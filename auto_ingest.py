import time
import subprocess
import os

from app.services.wazuh_reader import WazuhReader
from app.services.investigation import InvestigationEngine
from app.services.database import AlertDatabase


# =========================================================
# CONFIGURATION
# =========================================================

LOCAL_ALERT_FILE = "alerts.json"

WAZUH_KEY = os.path.expanduser(
    r"~\Downloads\wazuh-server.key.pem"
)

WAZUH_USER = "ubuntu"
WAZUH_HOST = "44.195.189.255"

REMOTE_ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

CHECK_INTERVAL = 30


# =========================================================
# SYNCHRONIZE WAZUH ALERTS
# =========================================================

def sync_wazuh_alerts():

    print()
    print("[+] Synchronizing Wazuh alerts...")

    command = [
        "ssh",
        "-i",
        WAZUH_KEY,
        f"{WAZUH_USER}@{WAZUH_HOST}",
        f"sudo cat {REMOTE_ALERT_FILE}"
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:

            print("[!] Wazuh synchronization failed.")

            if result.stderr:
                print(result.stderr.strip())

            return False

        # Save Wazuh alerts locally
        with open(
            LOCAL_ALERT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(result.stdout)

        print(
            "[+] Wazuh alerts synchronized successfully."
        )

        return True

    except Exception as error:

        print(
            f"[!] Synchronization error: {error}"
        )

        return False


# =========================================================
# PROCESS NEW ALERTS
# =========================================================

def process_new_alerts():

    reader = WazuhReader(
        LOCAL_ALERT_FILE
    )

    database = AlertDatabase()

    engine = InvestigationEngine()

    alerts = reader.read_alerts()

    new_alerts = 0

    for raw_alert in alerts:

        try:

            alert_id = raw_alert.get(
                "id",
                ""
            )

            if not alert_id:
                continue

            # Duplicate check
            if database.alert_exists(alert_id):
                continue

            # Parse Wazuh alert
            parsed_alert = reader.parse_alert(
                raw_alert
            )

            # Investigation
            investigation = engine.investigate(
                parsed_alert
            )

            # Save
            database.save_alert(
                parsed_alert,
                investigation
            )

            new_alerts += 1

            print(
                f"[+] NEW ALERT | "
                f"ID: {alert_id} | "
                f"Rule: {parsed_alert['rule']['id']} | "
                f"Severity: {parsed_alert['severity']} | "
                f"Risk: {investigation['risk_score']} "
                f"{investigation['risk_level']}"
            )

        except Exception as error:

            print(
                f"[!] Failed to process alert: {error}"
            )

    return new_alerts


# =========================================================
# MAIN MONITOR
# =========================================================

def main():

    print("=" * 65)

    print(
        "       SOC INVESTIGATION COPILOT"
    )

    print(
        "       AUTOMATIC WAZUH MONITOR"
    )

    print("=" * 65)

    print()

    print(
        f"[+] Checking Wazuh every "
        f"{CHECK_INTERVAL} seconds"
    )

    print(
        "[+] Press CTRL+C to stop"
    )

    print()

    while True:

        try:

            sync_success = sync_wazuh_alerts()

            if sync_success:

                new_alerts = process_new_alerts()

                if new_alerts == 0:

                    print(
                        "[*] No new alerts."
                    )

            else:

                print(
                    "[!] Skipping ingestion because "
                    "Wazuh synchronization failed."
                )

            print()

            time.sleep(
                CHECK_INTERVAL
            )

        except KeyboardInterrupt:

            print()

            print(
                "[+] Monitoring stopped."
            )

            break

        except Exception as error:

            print()

            print(
                f"[!] Monitor error: {error}"
            )

            print()

            time.sleep(
                CHECK_INTERVAL
            )


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()