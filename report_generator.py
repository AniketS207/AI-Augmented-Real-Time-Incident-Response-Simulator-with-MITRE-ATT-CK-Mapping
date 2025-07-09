from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_CENTER
import matplotlib.pyplot as plt
import tempfile
import os

def generate_report(df, filename="incident_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    report = []

    # Header
    title_style = ParagraphStyle(name="CenterTitle", parent=styles["Title"], alignment=TA_CENTER)
    report.append(Paragraph("🛡️ Incident Report - AI Threat Detection", title_style))
    report.append(Spacer(1, 20))

    chart_path = None  # Track temp file

    if df.empty:
        report.append(Paragraph("✅ No malicious activity detected.", styles["Normal"]))
    else:
        for _, row in df.iterrows():
            entry = f"""
<b>🕒 Time:</b> {row['TimeCreated']}<br/>
<b>🧾 Event ID:</b> {row['Id']}<br/>
<b>🎯 MITRE:</b> {row['MITRE_Technique']}<br/>
<b>📊 Severity:</b> {row['Severity']}<br/>
<b>⚠️ Risk Score:</b> {row['RiskScore']}<br/>
<b>📄 Message:</b> {str(row['Message'])[:500]}<br/><br/>
"""
            report.append(Paragraph(entry, styles["Normal"]))
            report.append(Spacer(1, 10))

        # Add MITRE bar chart
        chart_path = create_mitre_chart(df)
        if chart_path:
            report.append(Spacer(1, 20))
            report.append(Image(chart_path, width=450, height=250))

    # Generate the PDF
    doc.build(report)

    # Remove the temp image AFTER building
    if chart_path and os.path.exists(chart_path):
        os.remove(chart_path)

    print(f"✅ Report saved to {filename}")

def create_mitre_chart(df):
    mitre_counts = df['MITRE_Technique'].value_counts()
    if mitre_counts.empty:
        return None

    fig, ax = plt.subplots(figsize=(8, 4))
    mitre_counts.plot(kind='bar', ax=ax, color='skyblue')
    ax.set_title("MITRE Technique Frequency")
    ax.set_xlabel("Technique")
    ax.set_ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    plt.savefig(tmpfile.name, dpi=150)
    plt.close(fig)
    return tmpfile.name
