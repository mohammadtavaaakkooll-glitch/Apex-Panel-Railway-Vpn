FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tar gzip \
    && rm -rf /var/lib/apt/lists/*

# دانلود و استخراج mtg
RUN curl -L https://github.com/9seconds/mtg/releases/download/v2.2.8/mtg-2.2.8-linux-amd64.tar.gz \
    -o /tmp/mtg.tar.gz \
    && mkdir -p /tmp/mtg-extract \
    && tar -xzf /tmp/mtg.tar.gz -C /tmp/mtg-extract \
    && ls -la /tmp/mtg-extract/ \
    && find /tmp/mtg-extract -type f -name "mtg*" -exec mv {} /usr/local/bin/mtg \; \
    && chmod +x /usr/local/bin/mtg \
    && rm -rf /tmp/mtg.tar.gz /tmp/mtg-extract

# تست نصب
RUN /usr/local/bin/mtg --version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["python", "app.py"]
