FROM python:3.12-slim

WORKDIR /app

# نصب ابزارهای لازم برای دانلود و اجرای mtg
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tar gzip \
    && rm -rf /var/lib/apt/lists/*

# دانلود و نصب mtg (نسخه 2.2.8 - آخرین نسخه پایدار)
RUN curl -L https://github.com/9seconds/mtg/releases/download/v2.2.8/mtg-2.2.8-linux-amd64.tar.gz \
    -o /tmp/mtg.tar.gz \
    && tar -xzf /tmp/mtg.tar.gz -C /tmp \
    && mv /tmp/mtg /usr/local/bin/mtg \
    && chmod +x /usr/local/bin/mtg \
    && rm /tmp/mtg.tar.gz

# تایید نصب
RUN mtg --version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["python", "app.py"]
