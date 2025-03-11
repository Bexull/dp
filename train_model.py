import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from urllib.parse import urlparse
from scipy.sparse import hstack

# Пути к файлам
dataset_file = "C:/Users/Alpha/Desktop/url_checker/dataset.csv"
vectorizer_file = "C:/Users/Alpha/Desktop/url_checker/vectorizer.pkl"
model_file = "C:/Users/Alpha/Desktop/url_checker/url_classifier_model.pkl"

# Функция для извлечения домена из URL
def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

# Функция для извлечения дополнительных признаков
def extract_features(url):
    parsed = urlparse(url)
    features = {
        'length': len(url),
        'num_digits': sum(c.isdigit() for c in url),
        'num_subdomains': parsed.netloc.count('.'),
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'path_length': len(parsed.path),
        'query_length': len(parsed.query),
    }
    return features

# Загружаем датасет
data = pd.read_csv(dataset_file)
data["Домен"] = data["URL"].apply(get_domain)

# Создаем списки безопасных и фишинговых доменов
safe_domains = set(data[data["Безопасен"] == 1]["Домен"])
phishing_domains = set(data[data["Безопасен"] == 0]["Домен"])

# Добавляем новые признаки в датасет
data["length"] = data["URL"].apply(lambda x: len(x))
data["num_digits"] = data["URL"].apply(lambda x: sum(c.isdigit() for c in x))
data["num_subdomains"] = data["URL"].apply(lambda x: urlparse(x).netloc.count('.'))
data["has_https"] = data["URL"].apply(lambda x: 1 if urlparse(x).scheme == 'https' else 0)
data["path_length"] = data["URL"].apply(lambda x: len(urlparse(x).path))
data["query_length"] = data["URL"].apply(lambda x: len(urlparse(x).query))

# Разделяем данные на признаки и целевую переменную
X = data["URL"]
y = data["Безопасен"]

# Разделяем на тренировочные и тестовые данные
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Загружаем или создаем новый TF-IDF векторизатор
try:
    vectorizer = joblib.load(vectorizer_file)
    print("Загружен существующий TF-IDF векторизатор.")
except FileNotFoundError:
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
    print("Создан новый TF-IDF векторизатор.")

# Преобразуем данные в числовой формат
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# Добавляем новые признаки
X_train_features = data.loc[X_train.index, ["length", "num_digits", "num_subdomains", "has_https", "path_length", "query_length"]]
X_test_features = data.loc[X_test.index, ["length", "num_digits", "num_subdomains", "has_https", "path_length", "query_length"]]

# Объединяем TF-IDF и новые признаки
X_train_combined = hstack([X_train_tfidf, X_train_features])
X_test_combined = hstack([X_test_tfidf, X_test_features])

# Загружаем или создаем новый классификатор
try:
    model = joblib.load(model_file)
    print("Загружена существующая модель, выполняем дообучение...")
    model.fit(X_train_combined, y_train)
except FileNotFoundError:
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    print("Создана новая модель.")
    model.fit(X_train_combined, y_train)

# Оцениваем модель
predictions = model.predict(X_test_combined)
print("Accuracy:", accuracy_score(y_test, predictions))
print(classification_report(y_test, predictions))

# Сохраняем обновленные модель и векторизатор
joblib.dump(vectorizer, vectorizer_file)
joblib.dump(model, model_file)
joblib.dump(safe_domains, "C:/Users/Alpha/Desktop/url_checker/safe_domains.pkl")
joblib.dump(phishing_domains, "C:/Users/Alpha/Desktop/url_checker/phishing_domains.pkl")

print("Модель, векторизатор и списки доменов успешно сохранены!")