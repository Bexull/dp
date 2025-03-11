from flask import Flask, render_template, request, jsonify
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
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Нужен для хранения сессий

# Фиктивная база пользователей (замени на свою)
users = {"admin": "pbkdf2:sha256:150000$ZkG0H9…"}  # Пароли должны быть хешированы

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username in users and check_password_hash(users[username], password):
        session["user"] = username  # Сохраняем пользователя в сессии
        return "success"  # JS обработает это и перекинет на страницу

    return "error"

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html", user=session["user"])

@app.route("/welcome")
def welcome():
    return render_template("welcome.html")


# Загрузка модели, векторизатора и списков доменов
model = joblib.load("url_classifier_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")
safe_domains = joblib.load("safe_domains.pkl")
phishing_domains = joblib.load("phishing_domains.pkl")

# API-ключ для VirusTotal
VIRUSTOTAL_API_KEY = 'ab4c2ad3c4e97db57778947f4ad989d683e7f226d56981712926b03025ceec61'

# Функция для извлечения домена
def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

# Функция для извлечения дополнительных признаков
def extract_features(url):
    parsed = urlparse(url)
    return [
        len(url),  # Длина URL
        sum(c.isdigit() for c in url),  # Количество цифр
        parsed.netloc.count('.'),  # Количество поддоменов
        1 if parsed.scheme == 'https' else 0,  # HTTPS или нет
        len(parsed.path),  # Длина пути
        len(parsed.query)  # Длина query-параметров
    ]

# Функция проверки URL
def check_url(url):
    try:
        print(f"🔹 Проверяем URL: {url}")
        if not url.startswith(('http://', 'https://')):
            return "⚠️ Введите полный URL с http:// или https://"

        domain = get_domain(url)
        base_url = f"{urlparse(url).scheme}://{domain}"  # Основной домен

        print(f"🔹 Извлечён домен: {domain}")
        print(f"🔹 Базовый URL (без пути): {base_url}")

        # Проверяем, есть ли основной домен в безопасных или фишинговых списках
        if domain in safe_domains:
            return f"✅ Домен {domain} в списке безопасных. Весь сайт считается безопасным."
        if domain in phishing_domains:
            return f"⚠️ Домен {domain} в списке фишинговых. Весь сайт считается опасным."

        # Проверка сайта на доступность
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return f"⚠️ Сайт недоступен (код {response.status_code})."
        except requests.exceptions.RequestException:
            return "⚠️ Ошибка подключения к сайту."

        # Проверка модели ИИ
        if model and vectorizer:
            url_vectorized = vectorizer.transform([base_url])  # Проверяем только домен!
            url_features = np.array(extract_features(base_url)).reshape(1, -1)
            X_combined = hstack([url_vectorized, url_features])

            prediction = model.predict(X_combined)[0]
            ai_result = "✅ Модель ИИ считает сайт безопасным." if prediction == 1 else "⚠️ Модель ИИ считает сайт опасным."
        else:
            ai_result = "⚠️ Модель ИИ недоступна."

        # Анализ дополнительных факторов
        safety_report = ai_result
        safety_report += "\n" + check_ssl_certificate(url)
        safety_report += "\n" + analyze_html_content(response.text)
        safety_report += "\n" + analyze_domain(url)
        safety_report += "\n" + check_virustotal(url, VIRUSTOTAL_API_KEY)

        return safety_report
    except Exception as e:
        print(f"Ошибка в check_url: {e}")
        return f"⚠️ Ошибка обработки: {e}"


# Функция проверки SSL-сертификата
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
    except Exception as e:
        return f"⚠️ Ошибка при проверке SSL-сертификата: {e}"

# Функция анализа HTML-контента
def analyze_html_content(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    report = []
    if soup.find_all('form'):
        report.append("⚠️ Найдены формы. Возможен фишинг.")
    return "✅ HTML-контент не содержит явных признаков фишинга." if not report else "\n".join(report)

# Функция анализа домена
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

# Функция проверки через VirusTotal
def check_virustotal(url, api_key):
    try:
        params = {'apikey': api_key, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        result = response.json()
        if result.get('response_code') == 1:
            positives = result.get('positives', 0)
            return f"⚠️ VirusTotal: URL помечен как опасный ({positives} антивирусов)." if positives > 0 else "✅ VirusTotal: URL безопасен."
        return "⚠️ VirusTotal: URL не найден в базе."
    except Exception as e:
        return f"⚠️ Ошибка VirusTotal: {e}"

# Маршруты
@app.route('/', methods=['GET', 'POST'])
def index():
    recommendation = None
    if request.method == 'POST':
        url = request.form['url']
        recommendation = check_url(url)
    return render_template('index.html', recommendation=recommendation)

if __name__ == '__main__':
    app.run(debug=True)
