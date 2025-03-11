from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import joblib
from urllib.parse import urlparse
import ssl
import socket
from bs4 import BeautifulSoup
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import numpy as np
from scipy.sparse import hstack
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Подключение к MongoDB
uri = "mongodb+srv://Bexul:EM230267@cluster0.fzrfb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db = client.Url_checker
users_collection = db.MINE

# Загрузка модели
model = joblib.load("url_classifier_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")
safe_domains = joblib.load("safe_domains.pkl")
phishing_domains = joblib.load("phishing_domains.pkl")

VIRUSTOTAL_API_KEY = 'ab4c2ad3c4e97db57778947f4ad989d683e7f226d56981712926b03025ceec61'

# ====== Регистрация ======
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username").strip().lower()
    password = data.get("password")

    if users_collection.find_one({"username": {"$regex": f"^{username}$", "$options": "i"}}):
        return jsonify({"success": False, "message": "Пользователь уже существует."})

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({"username": username, "password": hashed_password})
    return jsonify({"success": True, "message": "Регистрация успешна!"})

# ====== Вход ======
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username").strip().lower()
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user["password"], password):
        session["user"] = username
        return jsonify({"success": True, "username": username})  # Отправляем имя пользователя

    return jsonify({"success": False, "message": "Неверные данные."})

# ====== Выход ======
@app.route("/logout", methods=["POST"])  # Теперь logout работает через POST
def logout():
    session.pop("user", None)
    return jsonify({"success": True})  # Отправляем JSON-ответ для обработки в JS

# ====== Главная страница ======
@app.route("/", methods=["GET", "POST"])
def index():
    recommendation = None
    username = session.get("user")  # Получаем имя пользователя из сессии
    if request.method == "POST":
        url = request.form["url"]
        recommendation = check_url(url)
    return render_template("index.html", recommendation=recommendation, username=username)


# ====== Дашборд (защищенная страница) ======
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))
    return f"Добро пожаловать, {session['user']}!"

# ====== Функции проверки URL ======
def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def extract_features(url):
    parsed = urlparse(url)
    return [
        len(url),
        sum(c.isdigit() for c in url),
        parsed.netloc.count('.'),
        1 if parsed.scheme == 'https' else 0,
        len(parsed.path),
        len(parsed.query),
    ]

def check_url(url):
    try:
        if not url.startswith(('http://', 'https://')):
            return "⚠️ Введите полный URL с http:// или https://"

        domain = get_domain(url)
        base_url = f"{urlparse(url).scheme}://{domain}"

        if domain in safe_domains:
            return f"✅ Домен {domain} в списке безопасных."
        if domain in phishing_domains:
            return f"⚠️ Домен {domain} в списке фишинговых."

        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return f"⚠️ Сайт недоступен (код {response.status_code})."

        if model and vectorizer:
            url_vectorized = vectorizer.transform([base_url])
            url_features = np.array(extract_features(base_url)).reshape(1, -1)
            X_combined = hstack([url_vectorized, url_features])
            prediction = model.predict(X_combined)[0]
            ai_result = "✅ Модель ИИ считает сайт безопасным." if prediction == 1 else "⚠️ Модель ИИ считает сайт опасным."
        else:
            ai_result = "⚠️ Модель ИИ недоступна."

        safety_report = ai_result
        safety_report += "\n" + check_ssl_certificate(url)
        safety_report += "\n" + analyze_html_content(response.text)
        safety_report += "\n" + analyze_domain(url)
        safety_report += "\n" + check_virustotal(url, VIRUSTOTAL_API_KEY)

        return safety_report
    except Exception as e:
        return f"⚠️ Ошибка обработки: {e}"

def check_ssl_certificate(url):
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
        not_after = cert.not_valid_after
        not_before = cert.not_valid_before
        current_time = datetime.utcnow()
        if current_time < not_before:
            return "⚠️ SSL-сертификат ещё не действителен."
        elif current_time > not_after:
            return "⚠️ SSL-сертификат истёк."
        return "✅ SSL-сертификат действителен."
    except Exception:
        return "⚠️ Ошибка при проверке SSL-сертификата."

def analyze_html_content(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    if soup.find_all("form"):
        return "⚠️ Найдены формы. Возможен фишинг."
    return "✅ HTML-контент не содержит явных признаков фишинга."

def analyze_domain(url):
    domain = urlparse(url).hostname
    report = []
    if len(domain) > 30:
        report.append("⚠️ Доменное имя слишком длинное.")
    if re.search(r'\d', domain):
        report.append("⚠️ Доменное имя содержит цифры.")
    if domain.count('.') > 2:
        report.append("⚠️ Доменное имя содержит много поддоменов.")
    return "✅ Доменное имя выглядит нормально." if not report else "\n".join(report)

def check_virustotal(url, api_key):
    try:
        params = {'apikey': api_key, 'resource': url}
        response = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params)
        result = response.json()
        if result.get("response_code") == 1:
            positives = result.get("positives", 0)
            return f"⚠️ VirusTotal: URL помечен как опасный ({positives} антивирусов)." if positives > 0 else "✅ VirusTotal: URL безопасен."
        return "⚠️ VirusTotal: URL не найден в базе."
    except Exception:
        return "⚠️ Ошибка VirusTotal."

if __name__ == "__main__":
    app.run(debug=True)
