FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential git libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# دانلود و ساخت MTProxy رسمی از سورس
RUN git clone https://github.com/TelegramMessenger/MTProxy.git /tmp/mtproxy \
    && cd /tmp/mtproxy \
    && make \
    && cp objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy \
    && chmod +x /usr/local/bin/mtproto-proxy \
    && rm -rf /tmp/mtproxy

# تست نصب
RUN mtproto-proxy --help 2>&1 | head -1 || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["python", "app.py"]
