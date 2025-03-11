import requests
import pandas as pd
from bs4 import BeautifulSoup
import io
import time

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
}


# Функция для получения списка фишинговых URL из PhishTank (через обход капчи)
def get_phishing_urls():
    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        urls = []
        page = 1
        while len(urls) < 500:
            response = session.get(f"https://phishtank.org/phish_search.php?page={page}&valid=y&active=y",
                                   headers=HEADERS)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.select("td:nth-child(2) a"):  # Берём ссылки из второй колонки
                url = link.text.strip()
                if url.startswith("http"):
                    urls.append(url)

            page += 1
            time.sleep(1)  # Делаем паузу, чтобы не получить бан
        return urls
    except Exception as e:
        print(f"Ошибка загрузки фишинговых URL: {e}")
        return []


# Функция для получения списка безопасных URL из новой ссылки Tranco
def get_safe_urls():
    try:
        response = requests.get("https://tranco-list.eu/download/WJZQ", headers=HEADERS)
        response.raise_for_status()
        df = pd.read_csv(io.StringIO(response.text), header=None)
        return df[1].dropna().tolist()
    except Exception as e:
        print(f"Ошибка загрузки безопасных URL: {e}")
        return []


# Загружаем данные
phishing_urls = get_phishing_urls()
safe_urls = get_safe_urls()

# Формируем датафрейм
phishing_data = pd.DataFrame({"URL": phishing_urls, "Безопасен": 0})
safe_data = pd.DataFrame({"URL": safe_urls, "Безопасен": 1})

# Объединяем данные и сохраняем в CSV
dataset = pd.concat([phishing_data, safe_data]).sample(frac=1).reset_index(drop=True)
dataset.to_csv("dataset.csv", index=False)

print("Датасет успешно обновлен!")
