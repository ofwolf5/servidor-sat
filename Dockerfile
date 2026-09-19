FROM python:3.11-slim

# Instalar dependencias del sistema necesarias para networking y rendering de PDFs (weasyprint/cairo/pango)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY . .

# Puerto expuesto
EXPOSE 10000

# Comando de inicio con Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
