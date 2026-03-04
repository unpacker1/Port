from flask import Flask, request, render_template_string, redirect, session, send_file
import xml.etree.ElementTree as ET
import hashlib
import os
import datetime
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import Table
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
app.secret_key = "supersecret"

USERNAME = "admin"
PASSWORD_HASH = hashlib.sha256("1234".encode()).hexdigest()

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
LOG_FILE = "logs.txt"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

def log_action(text):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {text}\n")

def parse_nmap_xml(filepath):
    tree = ET.parse(filepath)
    root = tree.getroot()
    results = []
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            portid = port.get("portid")
            state = port.find("state").get("state")
            service = port.find("service").get("name", "")
            version = port.find("service").get("version", "")
            results.append((portid, state, service, version))
    return results

def generate_chart(data):
    open_ports = [r for r in data if r[1] == "open"]
    labels = [r[0] for r in open_ports]
    values = [1]*len(labels)

    plt.figure()
    plt.bar(labels, values)
    plt.xticks(rotation=45)
    plt.tight_layout()
    chart_path = os.path.join(REPORT_FOLDER, "chart.png")
    plt.savefig(chart_path)
    plt.close()
    return chart_path

def generate_pdf(data):
    pdf_path = os.path.join(REPORT_FOLDER, "report.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("Pentest Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    table_data = [["Port", "State", "Service", "Version"]]
    for row in data:
        table_data.append(list(row))

    table = Table(table_data)
    elements.append(table)
    doc.build(elements)
    return pdf_path

HTML_LOGIN = """
<!DOCTYPE html>
<html><body style="background:#0f172a;color:white;text-align:center">
<h2>Login</h2>
<form method="POST">
<input name="username" placeholder="Username"><br><br>
<input name="password" type="password" placeholder="Password"><br><br>
<button>Login</button>
</form>
</body></html>
"""

HTML_PANEL = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{background:#0f172a;color:#e2e8f0;font-family:Arial}
.box{background:#1e293b;padding:20px;border-radius:10px;max-width:800px;margin:auto}
table{width:100%%;border-collapse:collapse}
td,th{border:1px solid #334155;padding:6px}
</style>
</head>
<body>
<div class="box">
<h2>Pentest Report Dashboard</h2>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" required>
<button>Upload XML</button>
</form>
<br>
<a href="/logout">Logout</a>
<hr>
{{content|safe}}
</div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pwd = hashlib.sha256(request.form["password"].encode()).hexdigest()
        if user == USERNAME and pwd == PASSWORD_HASH:
            session["logged"] = True
            return redirect("/panel")
    return HTML_LOGIN

@app.route("/panel", methods=["GET", "POST"])
def panel():
    if not session.get("logged"):
        return redirect("/")

    content = ""
    if request.method == "POST":
        file = request.files["file"]
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        data = parse_nmap_xml(filepath)
        log_action("XML uploaded")

        chart = generate_chart(data)
        pdf = generate_pdf(data)

        table_html = "<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>"
        for row in data:
            table_html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>"
        table_html += "</table>"

        content = table_html + f"<br><img src='/{chart}' width='100%%'><br><a href='/download'>Download PDF</a>"

    return render_template_string(HTML_PANEL, content=content)

@app.route("/download")
def download():
    return send_file(os.path.join(REPORT_FOLDER, "report.pdf"), as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)