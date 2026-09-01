import json


class WazuhReader:

    def __init__(self, file_path="alerts.json"):
        self.file_path = file_path

    def read_alerts(self):

        alerts = []

        with open(
            self.file_path,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                try:
                    alert = json.loads(line)
                    alerts.append(alert)

                except json.JSONDecodeError:
                    continue

        return alerts

    def parse_alert(self, alert):

        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})

        mitre = rule.get("mitre", {})

        mitre_ids = mitre.get("id", [])
        mitre_tactics = mitre.get("tactic", [])
        mitre_techniques = mitre.get("technique", [])

        return {
            "alert_id": alert.get("id", ""),

            "timestamp": alert.get(
                "timestamp",
                ""
            ),

            "rule": {
                "id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "description": rule.get(
                    "description",
                    ""
                )
            },

            "severity": self._get_severity(
                rule.get("level", 0)
            ),

            "agent": {
                "name": agent.get(
                    "name",
                    ""
                ),
                "ip": data.get(
                    "srcip",
                    ""
                )
            },

            "mitre": {
                "id": (
                    mitre_ids[0]
                    if mitre_ids
                    else ""
                ),

                "tactic": (
                    mitre_tactics[0]
                    if mitre_tactics
                    else ""
                ),

                "technique": (
                    mitre_techniques[0]
                    if mitre_techniques
                    else ""
                )
            },

            "data": data,

            "full_log": alert.get(
                "full_log",
                ""
            ),

            "process": {
                "image": "",
                "parent_image": "",
                "command_line": "",
                "user": data.get(
                    "dstuser",
                    ""
                )
            },

            "investigation_flags": []
        }

    @staticmethod
    def _get_severity(level):

        try:
            level = int(level)

        except (TypeError, ValueError):
            level = 0

        if level >= 12:
            return "Critical"

        elif level >= 9:
            return "High"

        elif level >= 6:
            return "Medium"

        else:
            return "Low"