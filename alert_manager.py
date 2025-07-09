import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

LOG_FILE = "logs/alerts.log"

def send_email_alert(subject, body):
    try:
        # Email env vars
        host = os.getenv("EMAIL_HOST")
        port = int(os.getenv("EMAIL_PORT"))
        user = os.getenv("EMAIL_USER")
        password = os.getenv("EMAIL_PASS")
        to_email = os.getenv("EMAIL_TO")

        # Construct email
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = user
        msg["To"] = to_email

        # Send via SMTP
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, to_email, msg.as_string())

        print("✅ Email alert sent.")

    except Exception as e:
        print(f"❌ Email alert failed: {e}")

    finally:
        # Log the alert to file
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {subject}\n{body}\n{'-'*60}\n"

        os.makedirs("logs", exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(log_entry)
