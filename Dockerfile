FROM python:3.10-slim
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app/webtool
COPY webtool/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY webtool .
EXPOSE 8001
CMD ["uwsgi", "--ini", "uwsgi.ini"]
