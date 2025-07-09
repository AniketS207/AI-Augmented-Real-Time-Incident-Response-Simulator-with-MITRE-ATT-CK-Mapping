# 🛡️ AI-Augmented Real-Time Incident Response Simulator

A real-time cybersecurity simulator and analyst dashboard powered by Python + Streamlit. This project simulates attacks, classifies threats with AI, maps them to MITRE ATT&CK, and triggers alerts with full PDF reporting and database logging.

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 💥 Attack Simulation | Buttons simulate PowerShell, curl, Registry, Rundll32 attacks |
| 🧠 AI Threat Classification | Labels events as Benign or Malicious with Risk Score and Severity |
| 🎯 MITRE Mapping | AI maps each threat to a MITRE ATT&CK Technique |
| 📄 PDF Report Generator | Generates incident reports with charts, metadata, and techniques |
| 📧 Email Alerting | Alerts triggered for malicious threats (SMTP + .env) |
| 📝 Log File Writing | Alerts are written to `logs/alerts.log` |
| 🗃️ SQLite Logging | Alerts also written to `logs/alerts.db` |
| 📤 Alert Downloads | Download alerts as `.txt` |
| 🧹 Clear Logs | One-click log cleaner |
| 🧭 Filters & Charts | Filter by threat type or severity + visual bar chart of MITRE hits |

---

## 📦 Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```

**requirements.txt**
```
streamlit
pandas
matplotlib
reportlab
python-dotenv
```

---

## 🛠️ Setup Instructions

1. **Clone the Repo**
   ```bash
git clone https://github.com/AniketS207/AI-Augmented-Real-Time-Incident-Response-Simulator-with-MITRE-ATT-CK-Mapping.git
cd "AI-Augmented-Real-Time-Incident-Response-Simulator-with-MITRE-ATT-CK-Mapping"
```
2. **Install Python Dependencies**
   ```bash
pip install -r requirements.txt
```
3. **Create Your .env File for Email Alerts**
   Create a `.env` file in the project root with the following content:
   ```env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
EMAIL_TO=recipient_email@gmail.com
```
   > Use Gmail App Passwords if you have 2FA enabled.

4. **Run the App**
   ```bash
streamlit run dashboard.py
```

---

## 📂 Project Structure

```
├── alert_manager.py         # Handles alert logging and email notifications
├── dashboard.py             # Streamlit dashboard UI
├── parse_sysmon.py          # Parses sysmon logs and applies AI detection
├── report_generator.py      # Generates PDF incident reports
├── requirements.txt         # Python dependencies
├── data/
│   ├── ai_features.csv      # AI-generated features
│   └── sysmon.csv           # Sysmon event data
├── logs/
│   ├── alerts.log           # Log file for alerts
│   └── alerts.db            # SQLite database for alerts
├── reports/
│   └── incident_report.pdf  # Generated PDF reports
├── Sysmon/                  # Sysmon binaries and config
│   ├── Sysmon.exe
│   ├── Sysmon64.exe
│   ├── Sysmon64a.exe
│   └── sysmonconfig-export.xml
└── ...
```

---

## 📢 Notes
- Ensure you have Python 3.8+ installed.
- For email alerts, configure your SMTP credentials in the `.env` file.
- Run `parse_sysmon.py` after simulating attacks to update AI features and trigger alerts.
- All logs and reports are saved in the `logs/` and `reports/` directories respectively.

---

## 📃 License

MIT License. See [LICENSE](LICENSE) for details.
