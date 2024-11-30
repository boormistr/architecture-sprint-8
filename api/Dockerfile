# Используем базовый образ Python
FROM python:3.9-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы приложения
COPY . .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем файл конфигурации логов
COPY logging_config.yaml /app/

RUN pip install pyyaml
# Запускаем Uvicorn с пользовательской конфигурацией логов
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "/app/logging_config.yaml"]