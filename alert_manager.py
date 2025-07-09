import os
import smtplib
import sqlite3
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "logs/alerts.log"
DB_FILE = "logs/alerts.db"

def log_to_sqlite(subject, body):
    os.makedirs("logs", exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            timestamp TEXT,
            subject TEXT,
            body TEXT
        )
    """)

    cursor.execute(
        "INSERT INTO alerts (timestamp, subject, body) VALUES (?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), subject, body)
    )

    conn.commit()
    conn.close()

def send_email_alert(subject, body):
    # ✅ Always log to alerts.log
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {subject}\n{body}\n{'-'*60}\n"

    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(log_entry)

    # ✅ Also log to SQLite
    log_to_sqlite(subject, body)

    # ✅ Attempt email alert
    try:
        host = os.getenv("EMAIL_HOST")
        port = int(os.getenv("EMAIL_PORT"))
        user = os.getenv("EMAIL_USER")
        password = os.getenv("EMAIL_PASS")
        to_email = os.getenv("EMAIL_TO")

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = user
        msg["To"] = to_email

        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, to_email, msg.as_string())

        print("✅ Email alert sent.")
    except Exception as e:
        print(f"❌ Email alert failed: {e}")
    