FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y \
    nmap \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libffi-dev \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libssl-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create required directories
RUN mkdir -p logs reports/output

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--reload", "--port", "8000"]