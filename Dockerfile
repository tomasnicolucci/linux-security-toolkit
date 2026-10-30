FROM python:3.13-slim AS base

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

# Shell scripts must use Unix line endings, even if they were edited on Windows.
RUN find src -name '*.sh' -exec sed -i 's/\r$//' {} +

RUN mkdir -p /app/data/integrity /app/data/logs


FROM base AS test

COPY requirements-dev.txt pyproject.toml ./

RUN pip install --no-cache-dir -r requirements-dev.txt

COPY tests ./tests
COPY samples ./samples

ENTRYPOINT ["python", "-m", "pytest"]
CMD ["-q"]


FROM base AS final

ENTRYPOINT ["python", "-m", "src.cli"]
