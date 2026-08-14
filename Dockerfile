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

# CPU-only torch by default. For a GPU image:
#   docker build --build-arg TORCH_EXTRAS=cuda .
ARG TORCH_EXTRAS=""

COPY pyproject.toml poetry.lock* /app/
RUN poetry install --only main --no-root ${TORCH_EXTRAS:+--extras $TORCH_EXTRAS}

COPY . /app

RUN poetry install --only main ${TORCH_EXTRAS:+--extras $TORCH_EXTRAS}

EXPOSE 9000

CMD ["poetry", "run", "fastmcp", "run", "vulnmcp/server.py", "--transport", "http", "--host", "0.0.0.0", "--port", "9000"]
