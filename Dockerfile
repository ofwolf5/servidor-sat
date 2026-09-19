# Imagen oficial con Python y dependencias nativas listas
FROM python:3.11-slim

# Instalar dependencias del sistema mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar requerimientos e instalar paquetes de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Instalar Chromium junto con todas las librerías del sistema Linux necesarias
RUN playwright install --with-deps chromium

# Copiar el código del servicio
COPY . .

# Puerto expuesto por Render
EXPOSE 10000

# Comando para iniciar la API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
