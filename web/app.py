from flask import Flask, render_template, request, redirect, url_for, session, Response
import sqlite3
import os
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

from app.services.report_generator import IncidentReportGenerator


app = Flask(__name__)

# ============================================================
# SECRET KEY
# ============================================================

app.secret_key = "soc-investigation-copilot-secret-key"


# ============================================================
# PROJECT ROOT + DATABASE
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

DATABASE = os.path.join(
    DATA_DIR,
    "soc.db"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    os.makedirs(DATA_DIR, exist_ok=True)

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# INITIALIZE LOGIN DATABASE
# ============================================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()

    connection.close()


# ============================================================
# CHECK USER EXISTS
# ============================================================

def user_exists():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM users
        LIMIT 1
    """)

    user = cursor.fetchone()

    connection.close()

    return user is not None


# ============================================================
# GET USER
# ============================================================

def get_user(username):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            password_hash
        FROM users
        WHERE username = ?
        LIMIT 1
    """, (username,))

    user = cursor.fetchone()

    connection.close()

    return user


# ============================================================
# UTC → IST TIMESTAMP
# ============================================================

def convert_to_ist(timestamp):

    if not timestamp:
        return "Not available"

    try:

        timestamp = str(timestamp).strip()

        # Wazuh timestamp example:
        # 2026-08-28T07:35:49.758+0000

        parsed = datetime.strptime(
            timestamp,
            "%Y-%m-%dT%H:%M:%S.%f%z"
        )

        ist = timezone(
            timedelta(hours=5, minutes=30)
        )

        converted = parsed.astimezone(ist)

        return converted.strftime(
            "%d %b %Y, %I:%M:%S %p IST"
        )

    except ValueError:

        try:

            parsed = datetime.strptime(
                timestamp,
                "%Y-%m-%dT%H:%M:%S%z"
            )

            ist = timezone(
                timedelta(hours=5, minutes=30)
            )

            converted = parsed.astimezone(ist)

            return converted.strftime(
                "%d %b %Y, %I:%M:%S %p IST"
            )

        except Exception:

            return timestamp

    except Exception:

        return timestamp


# ============================================================
# GET ALL ALERTS
# ============================================================

def get_alerts():

    connection = get_connection()

    cursor = connection.cursor()

    try:

        cursor.execute("""
            SELECT
                alert_id,
                agent_name,
                rule_id,
                soc_severity,
                risk_score,
                risk_level,
                mitre_id,
                investigation_status,
                created_at
            FROM alerts
            ORDER BY id DESC
        """)

        alerts = cursor.fetchall()

    except sqlite3.OperationalError as error:

        print("Database error:", error)

        alerts = []

    connection.close()

    return alerts


# ============================================================
# GET SINGLE ALERT
# ============================================================

def get_alert(alert_id):

    connection = get_connection()

    cursor = connection.cursor()

    try:

        cursor.execute("""
            SELECT *
            FROM alerts
            WHERE alert_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (alert_id,))

        alert = cursor.fetchone()

    except sqlite3.OperationalError as error:

        print("Database error:", error)

        alert = None

    connection.close()

    if alert is None:
        return None

    alert = dict(alert)

    # ========================================================
    # CONVERT WAZUH UTC TIMESTAMP TO IST
    # ========================================================

    if "timestamp" in alert:

        alert["timestamp"] = convert_to_ist(
            alert["timestamp"]
        )

    return alert


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if session.get("logged_in"):

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# LOGIN + FIRST TIME SETUP
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    # ========================================================
    # FIRST TIME SETUP
    # ========================================================

    if not user_exists():

        if request.method == "POST":

            username = request.form.get(
                "username",
                ""
            ).strip()

            password = request.form.get(
                "password",
                ""
            )

            confirm_password = request.form.get(
                "confirm_password",
                ""
            )

            # Username validation

            if not username:

                return render_template(
                    "login.html",
                    setup=True,
                    error="Username is required."
                )

            # Password validation

            if not password:

                return render_template(
                    "login.html",
                    setup=True,
                    error="Password is required."
                )

            # Confirm password

            if password != confirm_password:

                return render_template(
                    "login.html",
                    setup=True,
                    error="Passwords do not match."
                )

            # Password length

            if len(password) < 6:

                return render_template(
                    "login.html",
                    setup=True,
                    error="Password must contain at least 6 characters."
                )

            password_hash = generate_password_hash(
                password
            )

            connection = get_connection()

            cursor = connection.cursor()

            try:

                cursor.execute("""
                    INSERT INTO users
                    (
                        username,
                        password_hash
                    )
                    VALUES (?, ?)
                """, (
                    username,
                    password_hash
                ))

                connection.commit()

            except sqlite3.IntegrityError:

                connection.close()

                return render_template(
                    "login.html",
                    setup=True,
                    error="Username already exists."
                )

            connection.close()

            # Login automatically

            session["logged_in"] = True

            session["username"] = username

            return redirect(
                url_for("dashboard")
            )

        # First-time setup page

        return render_template(
            "login.html",
            setup=True
        )


    # ========================================================
    # NORMAL LOGIN
    # ========================================================

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = get_user(username)

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["logged_in"] = True

            session["username"] = user["username"]

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            setup=False,
            error="Invalid username or password."
        )

    return render_template(
        "login.html",
        setup=False
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    # Authentication check

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    # Get alerts

    alerts = get_alerts()

    # Summary

    total = len(alerts)

    critical = sum(
        1
        for alert in alerts
        if str(alert["risk_level"]).lower() == "critical"
    )

    high = sum(
        1
        for alert in alerts
        if str(alert["risk_level"]).lower() == "high"
    )

    medium = sum(
        1
        for alert in alerts
        if str(alert["risk_level"]).lower() == "medium"
    )

    low = sum(
        1
        for alert in alerts
        if str(alert["risk_level"]).lower() == "low"
    )

    # Render actual dashboard.html

    return render_template(
        "dashboard.html",
        alerts=alerts,
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        username=session.get(
            "username",
            "Security Analyst"
        )
    )


# ============================================================
# ALERT DETAILS
# ============================================================

@app.route("/alert/<alert_id>")
def alert_details(alert_id):

    # Login protection

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    alert = get_alert(alert_id)

    if alert is None:

        return "Alert not found", 404

    return render_template(
        "alert_details.html",
        alert=alert
    )


# ============================================================
# INCIDENT REPORT
# ============================================================

@app.route("/alert/<alert_id>/report")
def generate_report(alert_id):

    # Login protection

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    alert = get_alert(alert_id)

    if alert is None:

        return "Alert not found", 404

    try:

        report = IncidentReportGenerator.generate(
            alert
        )

    except Exception as error:

        return (
            f"Unable to generate report: {error}",
            500
        )

    filename = (
        f"SOC_Incident_Report_{alert_id}.txt"
    )

    return Response(
        report,
        mimetype="text/plain",
        headers={
            "Content-Disposition":
                f"attachment; filename={filename}"
        }
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print("")

    print("=" * 60)

    print(
        "          SOC INVESTIGATION COPILOT"
    )

    print("=" * 60)

    print("")

    print("Login URL:")

    print(
        "http://127.0.0.1:5000"
    )

    print("")

    if user_exists():

        print(
            "Account status : CONFIGURED"
        )

    else:

        print(
            "Account status : FIRST-TIME SETUP"
        )

    print("")

    print("Dashboard:")

    print(
        "Login -> /dashboard"
    )

    print("")

    print("=" * 60)

    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )