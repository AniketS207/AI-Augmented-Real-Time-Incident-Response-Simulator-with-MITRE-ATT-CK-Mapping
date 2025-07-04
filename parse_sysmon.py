# Import and Load CSV
import pandas as pd
from sklearn.ensemble import IsolationForest
from alert_manager import send_email_alert
from report_generator import generate_report

df = pd.read_csv("sysmon.csv", encoding='utf-8', low_memory=False)

# Clean + Filter Logs
event_ids = [1, 3, 10, 11]
df = df[df['Id'].isin(event_ids)]
df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], errors='coerce')
df = df.dropna(subset=['TimeCreated'])
df = df.sort_values(by='TimeCreated')

# Feature Engineering
df_feat = df.copy()
df_feat['EventType'] = df_feat['Id']
df_feat['Hour'] = df_feat['TimeCreated'].dt.hour
df_feat['ContainsEncoded'] = df_feat['Message'].str.contains('-enc', case=False, na=False).astype(int)
df_feat['ContainsDownload'] = df_feat['Message'].str.contains('curl|Invoke-WebRequest|wget|http', case=False, na=False).astype(int)
df_feat['ProcessCount'] = df_feat['Message'].str.count('Process')
df_feat = df_feat[['EventType', 'Hour', 'ContainsEncoded', 'ContainsDownload', 'ProcessCount']]

# AI Model (Isolation Forest)
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
df_feat['Anomaly'] = model.fit_predict(df_feat)
df_feat['AnomalyLabel'] = df_feat['Anomaly'].apply(lambda x: 'Malicious' if x == -1 else 'Normal')

# Output Results
print(df_feat[['EventType', 'Hour', 'AnomalyLabel']].head())


# Basic MITRE ATT&CK Technique Mapping
def map_mitre(row):
    message = row['Message'].lower()
    
    if '-enc' in message or 'frombase64string' in message:
        return 'T1059.001 - PowerShell'
    elif 'curl' in message or 'wget' in message or 'http' in message:
        return 'T1105 - Ingress Tool Transfer'
    elif 'reg add' in message or 'registry' in message:
        return 'T1112 - Modify Registry'
    elif 'taskkill' in message:
        return 'T1562.001 - Disable Security Tools'
    elif 'rundll32' in message:
        return 'T1218.011 - Signed Binary Proxy Execution: Rundll32'
    else:
        return 'T0000 - Unknown'

# Apply to original DataFrame
df['MITRE_Technique'] = df.apply(map_mitre, axis=1)


# Join AI result with original logs
df['AnomalyLabel'] = df_feat['AnomalyLabel']

# Show flagged events with mapped MITRE techniques
malicious_events = df[df['AnomalyLabel'] == 'Malicious']

print("\n⚠️ Potential Threats Mapped to MITRE:")
print(malicious_events[['TimeCreated', 'Id', 'AnomalyLabel', 'MITRE_Technique']].head())


# Save features + labels for dashboard
df_feat['MITRE_Technique'] = df['MITRE_Technique']
df_feat.to_csv("ai_features.csv", index=False)


# Alert on latest malicious event
malicious = df[df_feat['AnomalyLabel'] == 'Malicious']

if not malicious.empty:
    last = malicious.iloc[-1]
    subject = f"[ALERT] Malicious Activity Detected - Event ID {last['Id']}"
    body = f"""
Time: {last['TimeCreated']}
Event ID: {last['Id']}
MITRE Technique: {last['MITRE_Technique']}
Message: {last['Message'][:500]}
"""
    send_email_alert(subject, body)

# Only report on malicious entries
malicious = df[df_feat['AnomalyLabel'] == 'Malicious']

# Generate PDF
generate_report(malicious)
