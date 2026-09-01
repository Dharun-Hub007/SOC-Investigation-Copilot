import sqlite3
import json
from datetime import datetime
import os


class AlertDatabase:

    def __init__(self, database_path="data/soc.db"):
        self.database_path = database_path

        # Make sure data directory exists
        os.makedirs(
            os.path.dirname(self.database_path) or ".",
            exist_ok=True
        )

        self.create_database()
        self.upgrade_database()

    # -----------------------------------------------------
    # DATABASE CONNECTION
    # -----------------------------------------------------

    def connect(self):
        return sqlite3.connect(self.database_path)

    # -----------------------------------------------------
    # CREATE DATABASE
    # -----------------------------------------------------

    def create_database(self):

        connection = self.connect()
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                alert_id TEXT,

                agent_name TEXT,

                agent_ip TEXT,

                rule_id TEXT,

                rule_description TEXT,

                wazuh_level INTEGER,

                soc_severity TEXT,

                risk_score INTEGER,

                risk_level TEXT,

                mitre_id TEXT,

                mitre_tactic TEXT,

                mitre_technique TEXT,

                process_image TEXT,

                parent_process TEXT,

                user_name TEXT,

                timestamp TEXT,

                investigation_status TEXT,

                created_at TEXT,

                findings TEXT,

                recommendations TEXT
            )
        """)

        connection.commit()
        connection.close()

    # -----------------------------------------------------
    # UPGRADE DATABASE
    # -----------------------------------------------------

    def upgrade_database(self):

        connection = self.connect()
        cursor = connection.cursor()

        cursor.execute("PRAGMA table_info(alerts)")

        columns = [
            column[1]
            for column in cursor.fetchall()
        ]

        # Add findings column if missing
        if "findings" not in columns:

            cursor.execute("""
                ALTER TABLE alerts
                ADD COLUMN findings TEXT
            """)

        # Add recommendations column if missing
        if "recommendations" not in columns:

            cursor.execute("""
                ALTER TABLE alerts
                ADD COLUMN recommendations TEXT
            """)

        connection.commit()
        connection.close()

    # -----------------------------------------------------
    # SAVE ALERT
    # -----------------------------------------------------

    def save_alert(self, alert, investigation):

        connection = self.connect()
        cursor = connection.cursor()

        findings = json.dumps(
            investigation.get(
                "findings",
                []
            )
        )

        recommendations = json.dumps(
            investigation.get(
                "recommendations",
                []
            )
        )

        cursor.execute("""
            INSERT INTO alerts (

                alert_id,

                agent_name,

                agent_ip,

                rule_id,

                rule_description,

                wazuh_level,

                soc_severity,

                risk_score,

                risk_level,

                mitre_id,

                mitre_tactic,

                mitre_technique,

                process_image,

                parent_process,

                user_name,

                timestamp,

                investigation_status,

                created_at,

                findings,

                recommendations

            )

            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
        """, (

            alert.get(
                "alert_id",
                ""
            ),

            alert.get(
                "agent",
                {}
            ).get(
                "name",
                ""
            ),

            alert.get(
                "agent",
                {}
            ).get(
                "ip",
                ""
            ),

            alert.get(
                "rule",
                {}
            ).get(
                "id",
                ""
            ),

            alert.get(
                "rule",
                {}
            ).get(
                "description",
                ""
            ),

            alert.get(
                "rule",
                {}
            ).get(
                "level",
                0
            ),

            alert.get(
                "severity",
                "Low"
            ),

            investigation.get(
                "risk_score",
                0
            ),

            investigation.get(
                "risk_level",
                "Low"
            ),

            alert.get(
                "mitre",
                {}
            ).get(
                "id",
                ""
            ),

            alert.get(
                "mitre",
                {}
            ).get(
                "tactic",
                ""
            ),

            alert.get(
                "mitre",
                {}
            ).get(
                "technique",
                ""
            ),

            alert.get(
                "process",
                {}
            ).get(
                "image",
                ""
            ),

            alert.get(
                "process",
                {}
            ).get(
                "parent_image",
                ""
            ),

            alert.get(
                "process",
                {}
            ).get(
                "user",
                ""
            ),

            alert.get(
                "timestamp",
                ""
            ),

            "Investigated",

            datetime.now().isoformat(),

            findings,

            recommendations
        ))

        connection.commit()
        connection.close()

    # -----------------------------------------------------
    # CHECK IF ALERT EXISTS
    # -----------------------------------------------------

    def alert_exists(self, alert_id):

        connection = self.connect()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT 1
            FROM alerts
            WHERE alert_id = ?
            LIMIT 1
        """, (
            alert_id,
        ))

        result = cursor.fetchone()

        connection.close()

        return result is not None

    # -----------------------------------------------------
    # GET ALL ALERTS
    # -----------------------------------------------------

    def get_all_alerts(self):

        connection = self.connect()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT

                alert_id,

                agent_name,

                agent_ip,

                rule_id,

                rule_description,

                wazuh_level,

                soc_severity,

                risk_score,

                risk_level,

                mitre_id,

                mitre_tactic,

                mitre_technique,

                process_image,

                parent_process,

                user_name,

                timestamp,

                investigation_status,

                created_at,

                findings,

                recommendations

            FROM alerts

            ORDER BY id DESC
        """)

        rows = cursor.fetchall()

        connection.close()

        return rows

    # -----------------------------------------------------
    # GET ALERT BY ID
    # -----------------------------------------------------

    def get_alert_by_id(self, alert_id):

        connection = self.connect()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT

                alert_id,

                agent_name,

                agent_ip,

                rule_id,

                rule_description,

                wazuh_level,

                soc_severity,

                risk_score,

                risk_level,

                mitre_id,

                mitre_tactic,

                mitre_technique,

                process_image,

                parent_process,

                user_name,

                timestamp,

                investigation_status,

                created_at,

                findings,

                recommendations

            FROM alerts

            WHERE alert_id = ?

            ORDER BY id DESC

            LIMIT 1
        """, (
            alert_id,
        ))

        alert = cursor.fetchone()

        connection.close()

        if alert is None:
            return None

        # -------------------------------------------------
        # Convert findings JSON
        # -------------------------------------------------

        try:

            findings = (
                json.loads(alert[18])
                if alert[18]
                else []
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            findings = []

        # -------------------------------------------------
        # Convert recommendations JSON
        # -------------------------------------------------

        try:

            recommendations = (
                json.loads(alert[19])
                if alert[19]
                else []
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            recommendations = []

        # -------------------------------------------------
        # RETURN DICTIONARY
        # -------------------------------------------------

        return {

            "alert_id": alert[0],

            "agent_name": alert[1],

            "agent_ip": alert[2],

            "rule_id": alert[3],

            "rule_description": alert[4],

            "wazuh_level": alert[5],

            "soc_severity": alert[6],

            "risk_score": alert[7],

            "risk_level": alert[8],

            "mitre_id": alert[9],

            "mitre_tactic": alert[10],

            "mitre_technique": alert[11],

            "process_image": alert[12],

            "parent_process": alert[13],

            "user_name": alert[14],

            "timestamp": alert[15],

            "investigation_status": alert[16],

            "created_at": alert[17],

            "findings": findings,

            "recommendations": recommendations
        }