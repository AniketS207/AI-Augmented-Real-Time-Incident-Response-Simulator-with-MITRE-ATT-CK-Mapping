import smtplib
import os
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

def send_email_alert(subject, body):
    host = os.getenv("EMAIL_HOST")
    port = int(os.getenv("EMAIL_PORT"))
    user = os.getenv("EMAIL_USER")
    password = os.getenv("EMAIL_PASS")
    to_email = os.getenv("EMAIL_TO")

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_email

    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(msg)
            print("✅ Email alert sent.")
    except Exception as e:
        print(f"❌ Email alert failed: {e}")
