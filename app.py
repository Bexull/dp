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
from datetime import datetime, timezone
import whois
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
url_analysis_collection = db.url_analysis  # Коллекция для анализа URL


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
                "timestamp": datetime.now(timezone.utc)
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
        "timestamp": datetime.now(timezone.utc),
        "tx_hash": tx_hash.hex()
    })

    # 🔥 **Получаем количество жалоб на этот сайт**
    complaint_count = history_collection.count_documents({"url": url})

    print(f"⏳ Ожидание подтверждения транзакции {tx_hash.hex()}...")

    pending_tx = w3.eth.get_transaction(tx_hash)
    print(f"📌 Статус транзакции: {pending_tx}")
    print(f"✅ Жалоба добавлена в БД. Всего жалоб на {url}: {complaint_count}")

    # 🛑 **Добавляем в блокчейн, если жалоб >= 2**
    if complaint_count >= 2:
        print(f"⚠️ Сайт {url} получил {complaint_count} жалобы! Добавляем в блокчейн...")
        add_phishing_to_blockchain(url)

    return jsonify({
        "success": True,
        "message": "Жалоба отправлена!",
        "tx_hash": tx_hash.hex(),
        "complaints_count": complaint_count  # 👈 Добавили количество жалоб
    })



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

        # ✅ Проверка в белом/черном списках
        if domain in safe_domains:
            return f"✅ Домен {domain} в списке безопасных (100%)"
        if domain in phishing_domains:
            return f"⚠️ Домен {domain} в списке фишинговых (0%)"

        # 🔍 VirusTotal
        vt_report, vt_score = check_virustotal(url, VIRUSTOTAL_API_KEY)

        # 🧠 Проверка через ИИ
        if model and vectorizer:
            url_vectorized = vectorizer.transform([base_url])
            url_features = np.array(extract_features(base_url)).reshape(1, -1)
            X_combined = hstack([url_vectorized, url_features])

            # Вероятность, что сайт **безопасен**
            safe_probability = model.predict_proba(X_combined)[0][1] * 100
            safe_probability = round(safe_probability, 2)  # Округляем

            # 📌 Дополнительные проверки
            ssl_status = check_ssl_certificate(url)
            html_status = analyze_html_content(requests.get(url, timeout=5).text)
            domain_status, domain_age_factor = get_domain_age(domain)
            external_links_status, external_links_factor = check_external_links(url)
            redirect_status, redirect_factor = check_redirects(url)

            # 🛡️ Итоговый защитный фактор (0–1)
            protection_factor = (
                domain_age_factor + external_links_factor + redirect_factor
            ) / 3

            # Если VirusTotal считает сайт безопасным — минимум 90%
            if vt_report == "✅ VirusTotal: URL безопасен.":
                safe_probability = max(safe_probability, 90)

            # Если VirusTotal считает сайт опасным, но сайт выглядит нормально
            elif vt_score > 0:
                adjusted_probability = safe_probability * protection_factor
                safe_probability = max(15, adjusted_probability)

            ai_result = f"🔹 Вероятность безопасности сайта: {safe_probability}%"

            # 🔥 **Проверяем количество жалоб на сайт**
            complaint_count = history_collection.count_documents({"url": url})
            print(f"📌 Количество жалоб на {url}: {complaint_count}")

        else:
            ai_result = "⚠️ Модель ИИ недоступна."

        # 📊 Итоговый отчет
        safety_report = ai_result
        safety_report += "\n" + vt_report
        safety_report += "\n" + ssl_status
        safety_report += "\n" + html_status
        safety_report += "\n" + domain_status
        safety_report += "\n" + external_links_status
        safety_report += "\n" + redirect_status

        # Сохранение данных о проверке URL в коллекцию url_analysis
        url_analysis_collection.insert_one({
            "url": url,
            "domain": domain,
            "ai_result" : ai_result,
            "vt_report" : vt_report,
            "domain_status" : domain_status,
            "external_links_status" : external_links_status,
            "redirect_status" : redirect_status,
            "html_status" : html_status,
            "ssl_status" : ssl_status,
            "timestamp": datetime.now(timezone.utc)
        })

        return safety_report

    except Exception as e:
        return f"⚠️ Ошибка обработки: {e}"




def add_phishing_to_blockchain(url):
    site_hash = hashlib.sha256(url.encode()).hexdigest()

    # Получаем хеш последнего фишингового сайта
    try:
        last_site_hash = contract.functions.lastSiteHash().call()
        prev_site_hash = last_site_hash if last_site_hash != "" else "0x0"
    except Exception:
        prev_site_hash = "0x0"

    nonce = w3.eth.get_transaction_count(WALLET_ADDRESS, "pending")
    gas_price = w3.eth.gas_price

    tx = contract.functions.addPhishingSite(url, site_hash).build_transaction({
        "from": WALLET_ADDRESS,
        "gas": 200000,
        "gasPrice": gas_price,
        "nonce": nonce
    })

    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"🔴 Сайт {url} добавлен в блокчейн как фишинговый! Tx: {tx_hash.hex()}")
    return tx_hash.hex()


def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if not creation_date or not expiration_date:
            return "⚠️ Данные о возрасте домена недоступны.", 0.5  # Возвращаем строку и фактор риска

        # Преобразуем даты в UTC
        current_time = datetime.now(timezone.utc)
        domain_age_days = (current_time - creation_date).days
        days_to_expire = (expiration_date - current_time).days

        # 🔹 Определяем риск по возрасту домена
        if domain_age_days < 180:
            return f"⚠️ Домену {domain_age_days} дней – возможно, фишинг!", 0.2  # Высокий риск
        elif days_to_expire < 90:
            return f"⚠️ Домен истекает через {days_to_expire} дней – подозрительно!", 0.3
        else:
            return f"✅ Домену {domain_age_days} дней, истекает через {days_to_expire} дней.", 1.0  # Надёжный

    except Exception:
        return "⚠️ Ошибка при проверке возраста домена.", 0.5  # Вернуть строку и средний риск


def check_external_links(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a", href=True)

        external_links = [link["href"] for link in links if urlparse(link["href"]).netloc not in url]
        if len(external_links) > 30:
            return f"⚠️ Слишком много внешних ссылок ({len(external_links)}) – возможно, фишинг!", 0.2
        return f"✅ Внешних ссылок немного ({len(external_links)}).", 1.0
    except:
        return "⚠️ Ошибка при проверке внешних ссылок.", 0.5


def check_redirects(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        if len(response.history) > 2:
            return f"⚠️ Найдено {len(response.history)} перенаправления – возможно, фишинг!", 0.2
        return "✅ Перенаправлений нет или очень мало.", 1.0
    except:
        return "⚠️ Ошибка при проверке перенаправлений.", 0.5



def check_ssl_certificate(url):
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)  # ✅ Исправлено
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)  # ✅ Исправлено
        current_time = datetime.now(timezone.utc)  # ✅ Новый метод

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


import whois
from datetime import datetime, timezone


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
    app.run(host="0.0.0.0", port=8080, threaded=True)
