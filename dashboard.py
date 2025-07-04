import streamlit as st
import pandas as pd
from alert_manager import send_email_alert
from report_generator import generate_report
import os

# Load processed log file
df = pd.read_csv("sysmon.csv", encoding='utf-8', low_memory=False)
df_feat = pd.read_csv("ai_features.csv")  # AI results stored separately

# Merge AI result with original log
df['AnomalyLabel'] = df_feat['AnomalyLabel']
df['MITRE_Technique'] = df_feat['MITRE_Technique']
df['TimeCreated'] = pd.to_datetime(df['TimeCreated'])

# Page setup
st.set_page_config(page_title="AI-Powered Incident Response", layout="wide")
st.title("🛡️ AI-Augmented Real-Time Incident Response Simulator")
st.markdown("### 🔍 Detected Events")

# Filters
option = st.selectbox("Filter by Threat Type", ["All", "Malicious", "Normal"])
if option != "All":
    df = df[df['AnomalyLabel'] == option]

# Display table
st.dataframe(df[['TimeCreated', 'Id', 'AnomalyLabel', 'MITRE_Technique', 'Message']], use_container_width=True)

# Show MITRE stats
st.markdown("### 🎯 MITRE Technique Breakdown")
st.bar_chart(df['MITRE_Technique'].value_counts())

if st.button("📄 Generate Incident Report (PDF)"):
    malicious = df[df['AnomalyLabel'] == 'Malicious']
    generate_report(malicious)
    st.success("✅ Report generated as 'incident_report.pdf'")

    # Optional: show download link
    with open("incident_report.pdf", "rb") as file:
        btn = st.download_button(
            label="⬇️ Download Incident Report",
            data=file,
            file_name="incident_report.pdf",
            mime="application/pdf"
        )

