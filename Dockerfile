FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

RUN find src -name '*.sh' -exec sed -i 's/\r$//' {} +

RUN mkdir -p /app/data/integrity /app/data/logs

ENTRYPOINT ["python", "-m", "src.cli"]