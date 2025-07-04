from fpdf import FPDF
from datetime import datetime


class IncidentReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.add_font("DejaVu", "", "DejaVuSans.ttf", uni=True)
        self.add_font("DejaVu", "B", "DejaVuSans.ttf", uni=True)
        self.add_font("DejaVu", "I", "DejaVuSans.ttf", uni=True)
        self.set_font("DejaVu", "", 12)

    def header(self):
        self.set_font("DejaVu", "B", 16)
        self.cell(0, 10, "🛡️ Incident Report - AI Threat Detection", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "I", 8)
        self.cell(0, 10, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 0, "C")

    def add_entry(self, time, eid, mitre, msg):
        self.set_font("DejaVu", "", 12)
        clean_msg = str(msg).encode("utf-8", "ignore").decode("utf-8")
        self.multi_cell(0, 10, f"🕒 Time: {time}\n🧾 Event ID: {eid}\n🎯 MITRE: {mitre}\n📄 Message: {clean_msg[:500]}\n")
        self.ln(2)

def generate_report(df, filename="incident_report.pdf"):
    pdf = IncidentReportPDF()
    pdf.add_page()

    if df.empty:
        pdf.set_font("DejaVu", "I", 12)
        pdf.cell(0, 10, "✅ No malicious activity detected.", ln=True)
    else:
        for _, row in df.iterrows():
            pdf.add_entry(row['TimeCreated'], row['Id'], row['MITRE_Technique'], row['Message'])

    pdf.output(filename)
    print(f"✅ Report saved to {filename}")
