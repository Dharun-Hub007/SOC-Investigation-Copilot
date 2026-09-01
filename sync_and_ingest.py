import subprocess
import time

from app.services.wazuh_reader import WazuhReader
from app.services.investigation import InvestigationEngine
from app.services.database import AlertDatabase


# ============================================================
# CONFIGURATION
# ============================================================

REMOTE_HOST = "ubuntu@44.195.189.255"

SSH_KEY = r"C:\Users\narut\Downloads\wazuh-server.key.pem"

REMOTE_FILE = "/home/ubuntu/alerts.json"

LOCAL_FILE = "alerts.json"

CHECK_INTERVAL = 30


# ============================================================
# DOWNLOAD LATEST WAZUH ALERTS
# ============================================================

def sync_alerts():

    print("[+] Synchronizing Wazuh alerts...")

    command = [
        "scp",
        "-i",
        SSH_KEY,
        f"{REMOTE_HOST}:{REMOTE_FILE}",
        LOCAL_FILE
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode == 0:

        print("[+] Wazuh alerts synchronized successfully.")
        return True

    print("[!] Synchronization failed.")
    print(result.stderr)

    return False


# ============================================================
# PROCESS NEW ALERTS
# ============================================================

def process_alerts():

    reader = WazuhReader(LOCAL_FILE)

    database = AlertDatabase()

    engine = InvestigationEngine()

    alerts = reader.read_alerts()

    new_alerts = 0

    for raw_alert in alerts:

        try:

            alert_id = raw_alert.get("id", "")

            if not alert_id:
                continue

            if database.alert_exists(alert_id):
                continue

            parsed_alert = reader.parse_alert(raw_alert)

            investigation = engine.investigate(
                parsed_alert
            )

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
                f"[!] Failed alert: {error}"
            )

    return new_alerts


# ============================================================
# MAIN MONITOR
# ============================================================

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

            # Download latest Wazuh alerts
            if sync_alerts():

                # Process new alerts
                new_alerts = process_alerts()

                if new_alerts == 0:

                    print(
                        "[*] No new alerts."
                    )

            print()

            time.sleep(
                CHECK_INTERVAL
            )

        except KeyboardInterrupt:

            print()

            print(
                "[+] Wazuh monitoring stopped."
            )

            break

        except Exception as error:

            print(
                f"[!] Monitor error: {error}"
            )

            time.sleep(
                CHECK_INTERVAL
            )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()