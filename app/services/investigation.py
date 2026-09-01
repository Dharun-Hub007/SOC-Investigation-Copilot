class InvestigationEngine:
    """
    SOC Investigation Engine

    Analyzes parsed Wazuh alerts and produces:
    - SOC findings
    - Risk score (0-100)
    - Risk level
    - Investigation recommendations
    """

    def investigate(self, alert: dict) -> dict:

        score = 0
        findings = []
        recommendations = []

        rule = alert.get("rule", {})
        data = alert.get("data", {})
        process = alert.get("process", {})
        flags = alert.get("investigation_flags", [])
        mitre = alert.get("mitre", {})

        # ==================================================
        # 1. WAZUH RULE SEVERITY
        # ==================================================

        level = self._to_int(rule.get("level", 0))

        if level >= 15:
            score += 40
            findings.append(
                "Wazuh rule has a very high severity level."
            )

        elif level >= 12:
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

        # ==================================================
        # 2. RULE-SPECIFIC DETECTION
        # ==================================================

        rule_id = str(rule.get("id", ""))

        description = str(
            rule.get("description", "")
        ).lower()

        # --------------------------------------------------
        # SSH authentication success
        # --------------------------------------------------

        if rule_id == "5715" or "authentication success" in description:

            findings.append(
                "Successful SSH authentication was detected."
            )

            recommendations.append(
                "Verify that the SSH login was performed by "
                "an authorized user."
            )

            recommendations.append(
                "Review the source IP address and authentication time."
            )

            # Successful authentication alone is not malicious.
            score += 5

        # --------------------------------------------------
        # SSH authentication failure
        # --------------------------------------------------

        if (
            "authentication failure" in description
            or "authentication failed" in description
            or rule_id in ["5710", "5712"]
        ):

            score += 15

            findings.append(
                "Failed SSH authentication activity was detected."
            )

            recommendations.append(
                "Review the source IP for repeated authentication failures."
            )

        # --------------------------------------------------
        # Brute force
        # --------------------------------------------------

        if (
            "brute force" in description
            or "multiple authentication failures" in description
        ):

            score += 35

            findings.append(
                "Possible brute-force authentication activity was detected."
            )

            recommendations.append(
                "Investigate repeated authentication attempts "
                "from the source IP."
            )

            recommendations.append(
                "Consider blocking the source IP if malicious activity "
                "is confirmed."
            )

        # ==================================================
        # 3. MITRE ATT&CK
        # ==================================================

        mitre_id = mitre.get("id", "")

        if mitre_id:

            if isinstance(mitre_id, list):

                mitre_id = mitre_id[0] if mitre_id else ""

            findings.append(
                f"Alert is mapped to MITRE ATT&CK technique {mitre_id}."
            )

            score += 5

        # ==================================================
        # 4. INVESTIGATION FLAGS
        # ==================================================

        for flag in flags:

            flag_lower = str(flag).lower()

            if "suspicious command" in flag_lower:

                score += 20

                findings.append(
                    "Suspicious command execution was detected."
                )

                recommendations.append(
                    "Review the complete command line and determine "
                    "whether the command was authorized."
                )

            elif "unusual parent-child" in flag_lower:

                score += 30

                findings.append(
                    "An unusual parent-child process relationship "
                    "was detected."
                )

                recommendations.append(
                    "Investigate the parent and child processes."
                )

            elif "high integrity" in flag_lower:

                score += 15

                findings.append(
                    "The process executed with elevated integrity."
                )

                recommendations.append(
                    "Verify whether elevated privileges were required."
                )

        # ==================================================
        # 5. PROCESS ANALYSIS
        # ==================================================

        image = str(
            process.get("image", "")
        ).lower()

        parent_image = str(
            process.get("parent_image", "")
        ).lower()

        command_line = str(
            process.get("command_line", "")
        ).lower()

        # --------------------------------------------------
        # PowerShell
        # --------------------------------------------------

        if "powershell.exe" in image:

            score += 15

            findings.append(
                "PowerShell execution was observed."
            )

            recommendations.append(
                "Review the PowerShell command line and "
                "PowerShell operational logs."
            )

        # --------------------------------------------------
        # CMD
        # --------------------------------------------------

        if "cmd.exe" in image:

            score += 10

            findings.append(
                "Windows Command Shell execution was observed."
            )

            recommendations.append(
                "Review the command execution and verify "
                "whether it was authorized."
            )

        # --------------------------------------------------
        # Suspicious parent-child relationship
        # --------------------------------------------------

        if image and parent_image:

            if (
                "cmd.exe" in image
                and "postgres.exe" in parent_image
            ):

                score += 30

                findings.append(
                    "cmd.exe was launched by PostgreSQL, "
                    "which is an unusual parent-child relationship."
                )

                recommendations.append(
                    "Investigate why PostgreSQL launched Windows Command Shell."
                )

        # ==================================================
        # 6. COMMAND-LINE ANALYSIS
        # ==================================================

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
            "bitsadmin",
            "encodedcommand",
            "invoke-expression",
            "downloadstring"

        ]

        for suspicious_command in suspicious_commands:

            if suspicious_command in command_line:

                score += 15

                findings.append(
                    "The command line contains activity "
                    "that requires additional investigation."
                )

                recommendations.append(
                    "Review the complete command line and "
                    "determine whether the activity was authorized."
                )

                break

        # ==================================================
        # 7. NETWORK SOURCE INFORMATION
        # ==================================================

        source_ip = str(
            data.get("srcip", "")
        )

        if source_ip:

            findings.append(
                f"Source IP associated with the event: {source_ip}."
            )

            recommendations.append(
                "Verify whether the source IP belongs to an "
                "authorized user or trusted network."
            )

        # ==================================================
        # 8. USER ACTIVITY
        # ==================================================

        user = str(
            data.get(
                "dstuser",
                process.get("user", "")
            )
        )

        if user:

            findings.append(
                f"User account involved in the event: {user}."
            )

        # ==================================================
        # 9. FINAL SCORE
        # ==================================================

        score = min(score, 100)

        risk_level = self._get_risk_level(score)

        # ==================================================
        # 10. GENERAL SOC RECOMMENDATIONS
        # ==================================================

        if risk_level == "Critical":

            recommendations.append(
                "Immediately prioritize this alert for SOC investigation."
            )

            recommendations.append(
                "Correlate related events around the same timestamp."
            )

            recommendations.append(
                "Investigate the affected host, user, process and source IP."
            )

        elif risk_level == "High":

            recommendations.append(
                "Prioritize this alert for SOC analyst investigation."
            )

            recommendations.append(
                "Correlate related events around the same timestamp."
            )

        elif risk_level == "Medium":

            recommendations.append(
                "Perform additional log correlation before closing the alert."
            )

        else:

            recommendations.append(
                "Review the event and determine whether it represents "
                "expected administrative activity."
            )

        # ==================================================
        # 11. RETURN RESULT
        # ==================================================

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "findings": self._remove_duplicates(findings),
            "recommendations": self._remove_duplicates(
                recommendations
            )
        }

    # ======================================================
    # HELPERS
    # ======================================================

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