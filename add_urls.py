import pandas as pd

# Пути к файлам
dataset_file = "C:/Users/Alpha/Desktop/url_checker/dataset.csv"
new_urls_file = "C:/Users/Alpha/Desktop/url_checker/else/top-10000-domains"

# Загружаем существующий датасет
try:
    data = pd.read_csv(dataset_file)
except FileNotFoundError:
    # Если файл не существует, создаем новый DataFrame
    data = pd.DataFrame(columns=["URL", "Безопасен"])

# Читаем новые URL из текстового файла
with open(new_urls_file, "r", encoding="utf-8") as file:
    new_urls = file.read().splitlines()

# Создаем DataFrame для новых URL
new_data = pd.DataFrame({"URL": new_urls, "Безопасен": [1] * len(new_urls)})

# Объединяем старые и новые данные
data = pd.concat([data, new_data], ignore_index=True)

# Сохраняем обновленный датасет
data.to_csv(dataset_file, index=False)

print(f"Добавлено {len(new_urls)} новых URL. Общее количество записей: {len(data)}")