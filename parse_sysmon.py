import pandas as pd
from sklearn.ensemble import IsolationForest
from alert_manager import send_email_alert
from report_generator import generate_report
from datetime import datetime

# === LOAD SYSLOG DATA ===
df = pd.read_csv("data/sysmon.csv", encoding='utf-8', low_memory=False)

# Filter relevant event types
event_ids = [1, 3, 10, 11]
df = df[df['Id'].isin(event_ids)]
df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], errors='coerce')
df = df.dropna(subset=['TimeCreated']).sort_values(by='TimeCreated')

# === FEATURE ENGINEERING ===
df_feat = df.copy()
df_feat['EventType'] = df_feat['Id']
df_feat['Hour'] = df_feat['TimeCreated'].dt.hour
df_feat['ContainsEncoded'] = df_feat['Message'].str.contains('-enc', case=False, na=False).astype(int)
df_feat['ContainsDownload'] = df_feat['Message'].str.contains('curl|Invoke-WebRequest|wget|http', case=False, na=False).astype(int)
df_feat['ProcessCount'] = df_feat['Message'].str.count('Process')
df_feat = df_feat[['EventType', 'Hour', 'ContainsEncoded', 'ContainsDownload', 'ProcessCount']]

# === AI DETECTION ===
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
df_feat['Anomaly'] = model.fit_predict(df_feat)
df_feat['AnomalyLabel'] = df_feat['Anomaly'].apply(lambda x: 'Malicious' if x == -1 else 'Normal')

# === RISK SCORING ===
def calculate_risk(row):
    score = 0
    if row['ContainsEncoded']: score += 3
    if row['ContainsDownload']: score += 2
    if row['EventType'] == 1: score += 2
    if row['ProcessCount'] > 2: score += 1
    return score

def classify_risk(score):
    if score >= 6:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"

df_feat['RiskScore'] = df_feat.apply(calculate_risk, axis=1)
df_feat['Severity'] = df_feat['RiskScore'].apply(classify_risk)

# === MITRE ATT&CK MAPPING ===
def map_mitre(row):
    msg = row['Message'].lower()
    if '-enc' in msg or 'frombase64string' in msg:
        return 'T1059.001 - PowerShell'
    elif 'curl' in msg or 'wget' in msg or 'http' in msg:
        return 'T1105 - Ingress Tool Transfer'
    elif 'reg add' in msg or 'registry' in msg:
        return 'T1112 - Modify Registry'
    elif 'taskkill' in msg:
        return 'T1562.001 - Disable Security Tools'
    elif 'rundll32' in msg:
        return 'T1218.011 - Signed Binary Proxy Execution: Rundll32'
    else:
        return 'T0000 - Unknown'

df['MITRE_Technique'] = df.apply(map_mitre, axis=1)
df['AnomalyLabel'] = df_feat['AnomalyLabel']

# === JOIN RISK DATA BACK TO MAIN DF ===
df['Severity'] = df_feat['Severity']
df['RiskScore'] = df_feat['RiskScore']

# === SAVE FOR DASHBOARD ===
df_feat['MITRE_Technique'] = df['MITRE_Technique']
df_feat.to_csv("data/ai_features.csv", index=False)

# === PRINT THREAT SUMMARY ===
print("\n⚠️ Potential Threats Mapped to MITRE:")
print(df[df['AnomalyLabel'] == 'Malicious'][['TimeCreated', 'Id', 'AnomalyLabel', 'MITRE_Technique', 'Severity']].head())

# === EMAIL ALERT ===
malicious = df[df['AnomalyLabel'] == 'Malicious']
if not malicious.empty:
    last = malicious.iloc[-1]
    subject = f"[ALERT] Malicious Activity Detected - Event ID {last['Id']} ({last['Severity']})"
    body = f"""
🛡️ AI Threat Detection Alert

Time: {last['TimeCreated']}
Event ID: {last['Id']}
Severity: {last['Severity']}
Risk Score: {last['RiskScore']}
MITRE Technique: {last['MITRE_Technique']}
Message:
{last['Message'][:500]}
"""
    send_email_alert(subject, body)

# === GENERATE REPORT ===
generate_report(malicious)
