FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-rus \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs/review

ENV DISCORD_TOKEN=""
ENV GUILD_ID="0"
ENV LOG_CHANNEL_ID="0"
ENV MUTE_DURATION="3600"
ENV CONFIDENCE_THRESHOLD="0.55"

CMD ["python", "-u", "bot.py"]
