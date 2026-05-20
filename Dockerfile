FROM python:3.12-slim

ARG INSTALL_ML=false

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

# INSTALL_ML: false (default), cpu, or gpu
# cpu: installs torch from PyTorch CPU index (~1.6 GB image)
# gpu: installs torch from default PyPI with CUDA support (~5+ GB image)
# Version ranges match pyproject.toml.
RUN if [ "$INSTALL_ML" = "cpu" ]; then \
	pip install --no-cache-dir "torch>=2.0.0,<3.0.0" --index-url https://download.pytorch.org/whl/cpu && \
	pip install --no-cache-dir "transformers>=4.40.0,<5.0.0" && \
	poetry install --only main; \
	elif [ "$INSTALL_ML" = "gpu" ]; then \
	poetry install --only main -E ml; \
	else \
	poetry install --only main; \
	fi

EXPOSE 9000

CMD ["poetry", "run", "fastmcp", "run", "vulnmcp/server.py", "--transport", "http", "--host", "0.0.0.0", "--port", "9000"]
