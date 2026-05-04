FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	POETRY_VIRTUALENVS_CREATE=false \
	POETRY_NO_INTERACTION=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	curl \
	&& rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry

COPY pyproject.toml poetry.lock* /app/
RUN poetry install --only main --no-root

COPY . /app

RUN poetry install --only main

EXPOSE 9000

CMD ["poetry", "run", "fastmcp", "run", "vulnmcp/server.py", "--transport", "http", "--host", "0.0.0.0", "--port", "9000"]
