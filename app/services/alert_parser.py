from typing import Any, Dict, Optional


class WazuhAlertParser:
    """
    Parses a Wazuh alert and extracts the important
    information required for SOC investigation.
    """

    def __init__(self, alert: Dict[str, Any]):
        self.alert = alert

    def parse(self) -> Dict[str, Any]:
        rule = self.alert.get("rule", {})
        agent = self.alert.get("agent", {})
        data = self.alert.get("data", {})
        win = data.get("win", {})
        eventdata = win.get("eventdata", {})
        system = win.get("system", {})

        result = {
            "alert_id": self.alert.get("id"),

            "agent": {
                "id": agent.get("id"),
                "name": agent.get("name"),
                "ip": agent.get("ip"),
            },

            "rule": {
                "id": rule.get("id"),
                "description": rule.get("description"),
                "level": rule.get("level"),
                "groups": rule.get("groups"),
            },

            "mitre": {
                "id": rule.get("mitre", {}).get("id"),
                "tactic": rule.get("mitre", {}).get("tactic"),
                "technique": rule.get("mitre", {}).get("technique"),
            },

            "event": {
                "id": system.get("eventID"),
                "channel": system.get("channel"),
                "computer": system.get("computer"),
                "timestamp": self.alert.get("timestamp"),
            },

            "process": {
                "image": eventdata.get("image"),
                "command_line": eventdata.get("commandLine"),
                "parent_image": eventdata.get("parentImage"),
                "parent_command_line": eventdata.get("parentCommandLine"),
                "user": eventdata.get("user"),
                "parent_user": eventdata.get("parentUser"),
                "integrity_level": eventdata.get("integrityLevel"),
                "process_id": eventdata.get("processId"),
                "parent_process_id": eventdata.get("parentProcessId"),
                "hashes": eventdata.get("hashes"),
            },
        }

        result["severity"] = self._calculate_severity(
            rule.get("level", 0)
        )

        result["investigation_flags"] = self._detect_flags(
            eventdata,
            rule
        )

        return result

    def _calculate_severity(self, level: Any) -> str:
        """
        Converts Wazuh rule level into a simple SOC severity.
        """

        try:
            level = int(level)
        except (TypeError, ValueError):
            return "Unknown"

        if level >= 12:
            return "Critical"
        elif level >= 9:
            return "High"
        elif level >= 6:
            return "Medium"
        else:
            return "Low"

    def _detect_flags(
        self,
        eventdata: Dict[str, Any],
        rule: Dict[str, Any]
    ) -> list:

        flags = []

        command_line = str(
            eventdata.get("commandLine", "")
        ).lower()

        parent_image = str(
            eventdata.get("parentImage", "")
        ).lower()

        image = str(
            eventdata.get("image", "")
        ).lower()

        # Suspicious command execution
        suspicious_commands = [
            "powershell",
            "cmd.exe",
            "whoami",
            "ipconfig",
            "net user",
            "net localgroup",
            "reg.exe",
            "schtasks",
            "wmic",
            "certutil",
        ]

        for command in suspicious_commands:
            if command in command_line:
                flags.append(
                    f"Suspicious command detected: {command}"
                )

        # Suspicious parent-child relationship
        if "cmd.exe" in image and "postgres.exe" in parent_image:
            flags.append(
                "Unusual parent-child process relationship"
            )

        # High integrity process
        if str(
            eventdata.get("integrityLevel", "")
        ).lower() == "high":
            flags.append(
                "Process running with High integrity"
            )

        # MITRE mapping
        mitre = rule.get("mitre", {})

        if mitre.get("id"):
            flags.append(
                f"MITRE ATT&CK technique: {mitre.get('id')}"
            )

        return flags


def parse_wazuh_alert(
    alert: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convenience function for parsing a Wazuh alert.
    """

    parser = WazuhAlertParser(alert)

    return parser.parse()