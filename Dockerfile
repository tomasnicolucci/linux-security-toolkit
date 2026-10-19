FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

RUN mkdir -p /app/data/integrity /app/data/logs

ENTRYPOINT ["python", "-m", "src.cli"]