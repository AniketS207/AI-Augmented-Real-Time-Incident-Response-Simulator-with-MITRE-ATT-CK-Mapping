import streamlit as st
import pandas as pd
from alert_manager import send_email_alert
from report_generator import generate_report
import streamlit.components.v1 as components
import base64
import os

# ✅ First Streamlit command
st.set_page_config(page_title="AI-Powered Incident Response", layout="wide")

# 🔄 Manual Refresh
if st.button("🔄 Refresh Logs"):
    st.experimental_rerun()

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
df['TimeCreated'] = pd.to_datetime(df['TimeCreated'])

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
