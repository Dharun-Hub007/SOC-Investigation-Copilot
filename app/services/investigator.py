class InvestigationEngine:
    """
    Analyzes parsed Wazuh alerts and calculates
    a SOC-oriented risk score.
    """

    def investigate(self, alert: dict) -> dict:

        score = 0
        findings = []
        recommendations = []

        rule = alert.get("rule", {})
        process = alert.get("process", {})
        flags = alert.get("investigation_flags", [])

        # -------------------------------------------------
        # 1. Wazuh rule severity
        # -------------------------------------------------

        level = self._to_int(rule.get("level"))

        if level >= 12:

            score += 30

            findings.append(
                "Wazuh rule has a critical severity level."
            )

        elif level >= 9:

            score += 20

            findings.append(
                "Wazuh rule has a high severity level."
            )

        elif level >= 6:

            score += 10

            findings.append(
                "Wazuh rule has a medium severity level."
            )

        # -------------------------------------------------
        # 2. Investigation flags
        # -------------------------------------------------

        for flag in flags:

            flag_lower = str(flag).lower()

            if "suspicious command" in flag_lower:

                score += 20

                findings.append(
                    "Suspicious command execution was detected."
                )

                recommendations.append(
                    "Review the complete command line and determine "
                    "whether the command was expected."
                )

            elif "unusual parent-child" in flag_lower:

                score += 30

                findings.append(
                    "An unusual parent-child process relationship "
                    "was detected."
                )

                recommendations.append(
                    "Investigate the parent process and determine "
                    "why it launched the child process."
                )

            elif "high integrity" in flag_lower:

                score += 15

                findings.append(
                    "The process executed with High integrity."
                )

                recommendations.append(
                    "Verify whether elevated privileges were required."
                )

            elif "mitre" in flag_lower:

                score += 10

                findings.append(
                    "The alert is associated with a MITRE ATT&CK technique."
                )

        # -------------------------------------------------
        # 3. Process-specific investigation
        # -------------------------------------------------

        image = str(
            process.get("image", "")
        ).lower()

        parent_image = str(
            process.get("parent_image", "")
        ).lower()

        command_line = str(
            process.get("command_line", "")
        ).lower()

        # -------------------------------------------------
        # PowerShell detection
        # -------------------------------------------------

        if "powershell.exe" in image:

            score += 10

            findings.append(
                "PowerShell execution was observed."
            )

            recommendations.append(
                "Review the PowerShell command line and "
                "PowerShell operational logs."
            )

        # -------------------------------------------------
        # Windows Command Shell detection
        # -------------------------------------------------

        if "cmd.exe" in image:

            score += 5

            findings.append(
                "Windows Command Shell execution was observed."
            )

            recommendations.append(
                "Review the Windows command line activity "
                "and verify whether the execution was authorized."
            )

        # -------------------------------------------------
        # Suspicious parent-child relationship
        # -------------------------------------------------

        if image and parent_image:

            if (
                "cmd.exe" in image
                and "postgres.exe" in parent_image
            ):

                findings.append(
                    "cmd.exe was launched by PostgreSQL, "
                    "which is an unusual parent-child process relationship."
                )

                recommendations.append(
                    "Investigate why the PostgreSQL process "
                    "launched Windows Command Shell."
                )

        # -------------------------------------------------
        # Command-line analysis
        # -------------------------------------------------

        suspicious_commands = [
            "powershell",
            "cmd.exe",
            "whoami",
            "net user",
            "net localgroup",
            "ipconfig",
            "tasklist",
            "reg add",
            "schtasks",
            "wmic",
            "certutil",
            "bitsadmin"
        ]

        for suspicious_command in suspicious_commands:

            if suspicious_command in command_line:

                findings.append(
                    "The command line contains activity that "
                    "requires additional investigation."
                )

                recommendations.append(
                    "Review the complete command line and "
                    "determine whether the activity was authorized."
                )

                break

        # -------------------------------------------------
        # 4. Determine final risk
        # -------------------------------------------------

        score = min(score, 100)

        risk_level = self._get_risk_level(score)

        # -------------------------------------------------
        # 5. Add general recommendations
        # -------------------------------------------------

        if risk_level in ["High", "Critical"]:

            recommendations.append(
                "Prioritize this alert for SOC analyst investigation."
            )

            recommendations.append(
                "Check related events around the same timestamp."
            )

            recommendations.append(
                "Investigate the process tree and user activity."
            )

        elif risk_level == "Medium":

            recommendations.append(
                "Perform additional log correlation before closing."
            )

        else:

            recommendations.append(
                "Review the event and determine whether it is "
                "expected administrative activity."
            )

        # -------------------------------------------------
        # 6. Return investigation result
        # -------------------------------------------------

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "findings": self._remove_duplicates(findings),
            "recommendations": self._remove_duplicates(
                recommendations
            ),
        }

    # -----------------------------------------------------
    # Helper functions
    # -----------------------------------------------------

    @staticmethod
    def _to_int(value) -> int:

        try:
            return int(value)

        except (TypeError, ValueError):

            return 0

    @staticmethod
    def _get_risk_level(score: int) -> str:

        if score >= 80:

            return "Critical"

        elif score >= 60:

            return "High"

        elif score >= 30:

            return "Medium"

        else:

            return "Low"

    @staticmethod
    def _remove_duplicates(items: list) -> list:

        return list(dict.fromkeys(items))


def investigate_alert(alert: dict) -> dict:
    """
    Convenience function for running the investigation engine.
    """

    engine = InvestigationEngine()

    return engine.investigate(alert)