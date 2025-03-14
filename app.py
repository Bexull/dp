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
from dotenv import load_dotenv
from web3 import Web3
import json
from contract_config import (CONTRACT_ABI, CONTRACT_ADDRESS)
# Подключение к QuickNode
load_dotenv()
from dotenv import load_dotenv
import os
import hashlib


dotenv_path = os.path.join(os.path.dirname(__file__), "node_server", ".env")
load_dotenv(dotenv_path)

RPC_URL = os.getenv("RPC_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS")

print(f"RPC_URL: {RPC_URL}")
print(f"PRIVATE_KEY: {PRIVATE_KEY}")
print(f"CONTRACT_ADDRESS: {CONTRACT_ADDRESS}")
print(f"WALLET_ADDRESS: {WALLET_ADDRESS}")



w3 = Web3(Web3.HTTPProvider(RPC_URL))

if w3.is_connected():
    print("✅ Web3 подключен к блокчейну!")
else:
    print("❌ Ошибка подключения к блокчейну!")

with open("contract_abi.json", "r") as f:
    contract_data = json.load(f)

if isinstance(contract_data, dict) and "abi" in contract_data:
    CONTRACT_ABI = contract_data["abi"]
else:
    raise ValueError("❌ Ошибка: 'contract_abi.json' не содержит ключ 'abi'. Проверьте формат файла.")





app = Flask(__name__)
app.secret_key = "your_secret_key"

# Подключение к MongoDB
uri = "mongodb+srv://ismailfarkhat:GameOfThrones04@cluster0.e0iti.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db = client.Url_checker  # База данных

users_collection = db.MINE  # Коллекция пользователей
history_collection = db.history  # Коллекция для хранения истории проверок


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
    email = data.get("email").strip().lower()
    password = data.get("password")

    if users_collection.find_one({"username": username}):
        return jsonify({"success": False, "message": "Имя пользователя уже занято."})

    if users_collection.find_one({"email": email}):
        return jsonify({"success": False, "message": "E-mail уже зарегистрирован."})

    hashed_password = generate_password_hash(password)
    new_user = {
        "username": username,
        "email": email,
        "password": hashed_password,
        "registration_date": datetime.utcnow(),  # Дата регистрации
        "last_login": None  # Последний вход пока пустой
    }

    users_collection.insert_one(new_user)
    return jsonify({"success": True, "message": "Регистрация успешна!"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username").strip().lower()
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user["password"], password):
        session["user"] = username
        session["recommendation"] = None  # Очищаем результат проверки URL
        return jsonify({"success": True})

    return jsonify({"success": False, "message": "Неверные данные."})



# ====== Выход ======
@app.route("/logout", methods=["GET"])
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))



# ====== Главная страница ======
# ====== Проверка URL и сохранение истории ======
@app.route("/", methods=["GET", "POST"])
def index():
    username = session.get("user")  # Получаем имя пользователя
    recommendation = None
    user_history = []

    if request.method == "POST":
        url = request.form["url"]
        recommendation = check_url(url)

        if username:  # Если пользователь авторизован, сохраняем в историю
            history_collection.insert_one({
                "username": username,
                "url": url,
                "timestamp": datetime.utcnow()
            })

    # Загружаем историю проверок пользователя
    if username:
        user_history = [entry["url"] for entry in history_collection.find({"username": username})]

    return render_template("index.html", recommendation=recommendation, username=username, history=user_history)



# ====== Дашборд (защищенная страница) ======
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))
    return f"Добро пожаловать, {session['user']}!"

# Подключение к контракту
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

# ====== Жалоба на URL ======
from bson import ObjectId

@app.route("/report", methods=["POST"])
def report_url():
    data = request.get_json()
    url = data.get("url")

    if "user" not in session:
        return jsonify({"success": False, "message": "Требуется авторизация!"})

    username = session["user"]
    user = users_collection.find_one({"username": username})

    if not user:
        return jsonify({"success": False, "message": "Ошибка авторизации!"})

    user_id = str(user["_id"])  # ID пользователя в MongoDB
    email = user["email"]  # Email пользователя

    # 🔍 **Проверяем, жаловался ли этот пользователь**
    existing_complaint = history_collection.find_one({"user_id": user_id, "url": url})
    if existing_complaint:
        return jsonify({"success": False, "message": "Вы уже отправляли жалобу на этот сайт!"})

    # 🔹 Получаем nonce перед отправкой транзакции
    nonce = w3.eth.get_transaction_count(WALLET_ADDRESS, "pending")

    # 🔹 Устанавливаем цену газа вручную
    gas_price = int(w3.eth.gas_price * 1.2)  # Увеличиваем цену газа на 20%

    # 🔹 Отправляем user_id и email в контракт
    tx = contract.functions.reportURL(url, user_id, email).build_transaction({
        "from": WALLET_ADDRESS,
        "gas": 200000,
        "gasPrice": gas_price,
        "nonce": nonce
    })

    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    # 🔹 Ожидаем подтверждения транзакции
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)  # 5 минут

    # ✅ **Сохраняем жалобу в MongoDB**
    history_collection.insert_one({
        "user_id": user_id,
        "email": email,
        "username": username,
        "url": url,
        "timestamp": datetime.utcnow(),
        "tx_hash": tx_hash.hex()
    })

    print(f"⏳ Ожидание подтверждения транзакции {tx_hash.hex()}...")

    pending_tx = w3.eth.get_transaction(tx_hash)
    print(f"📌 Статус транзакции: {pending_tx}")

    return jsonify({"success": True, "message": "Жалоба отправлена!", "tx_hash": tx_hash.hex()})



@app.route("/complaints/<path:url>", methods=["GET"])
def get_complaint_count(url):
    try:
        count = contract.functions.getComplaintCount(url).call()
        return jsonify({"url": url, "complaints": count})
    except Exception as e:
        return jsonify({"success": False, "message": f"Ошибка получения жалоб: {str(e)}"})

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

        # ✅ Проверка на "белые" и "черные" списки
        if domain in safe_domains:
            return f"✅ Домен {domain} в списке безопасных (100%)"
        if domain in phishing_domains:
            return f"⚠️ Домен {domain} в списке фишинговых (0%)"

        # 🔍 Проверка через VirusTotal
        vt_report, vt_score = check_virustotal(url, VIRUSTOTAL_API_KEY)

        # 🧠 Проверяем ИИ-модель
        if model and vectorizer:
            url_vectorized = vectorizer.transform([base_url])
            url_features = np.array(extract_features(base_url)).reshape(1, -1)
            X_combined = hstack([url_vectorized, url_features])

            # Получаем вероятность, что сайт **безопасен**
            safe_probability = model.predict_proba(X_combined)[0][1] * 100
            safe_probability = round(safe_probability, 2)  # Округляем

            # 🔎 Дополнительные проверки (SSL, HTML, Домен)
            ssl_status = check_ssl_certificate(url)
            html_status = analyze_html_content(requests.get(url, timeout=5).text)
            domain_status = analyze_domain(url)

            # 🛡️ Фактор защиты (0 — плохой, 1 — нормальный)
            protection_factor = 0
            if "✅" in ssl_status:
                protection_factor += 0.3
            if "✅" in html_status:
                protection_factor += 0.3
            if "✅" in domain_status:
                protection_factor += 0.3

            # Если VirusTotal считает сайт безопасным — минимум 90%
            if vt_report == "✅ VirusTotal: URL безопасен.":
                safe_probability = max(safe_probability, 90)

            # Если VirusTotal считает сайт опасным, но сайт выглядит нормально
            elif vt_score > 0:
                adjusted_probability = safe_probability * protection_factor
                safe_probability = max(15, adjusted_probability)

            ai_result = f"🔹 Вероятность безопасности сайта: {safe_probability}%"

        else:
            ai_result = "⚠️ Модель ИИ недоступна."

        # 📊 Формируем итоговый отчет
        safety_report = ai_result
        safety_report += "\n" + vt_report  # Добавляем результат VirusTotal
        safety_report += "\n" + ssl_status
        safety_report += "\n" + html_status
        safety_report += "\n" + domain_status

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
            if positives > 0:
                return f"⚠️ VirusTotal: URL помечен как опасный ({positives} антивирусов).", positives
            else:
                return "✅ VirusTotal: URL безопасен.", 0

        return "⚠️ VirusTotal: URL не найден в базе.", -1

    except Exception:
        return "⚠️ Ошибка VirusTotal.", -1





if __name__ == "__main__":
    app.run(debug=True)