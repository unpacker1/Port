from flask import Flask, request, render_template_string

app = Flask(__name__)

# SADECE KENDİ TEST IP'LERİN
ALLOWED_TARGETS = ["127.0.0.1", "localhost"]

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Lab Port Scanner</title>
</head>
<body>
    <h2>Local Lab Scanner (Eğitim Amaçlı)</h2>
    <form method="POST">
        Hedef IP:
        <input type="text" name="target" required>
        <button type="submit">Tara</button>
    </form>
    <pre>{{result}}</pre>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    if request.method == "POST":
        target = request.form.get("target")

        if target not in ALLOWED_TARGETS:
            result = "❌ Bu hedefe izin verilmiyor!"
        else:
            # Demo çıktı
            result = f"""
Starting Demo Scan on {target}

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https

Scan Completed (Demo Mode)
"""
    return render_template_string(HTML_PAGE, result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)