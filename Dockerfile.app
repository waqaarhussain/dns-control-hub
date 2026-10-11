FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir cryptography==50.0.1
WORKDIR /app
ENV PYTHONUNBUFFERED=1
