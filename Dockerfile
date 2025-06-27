FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml poetry.lock* /app/
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-dev --no-interaction --no-ansi
COPY src/ /app/src/
RUN pip install -e .[dev] && \
    python -c "import uyubox_core; uyubox_core.harden_linux()"
ENTRYPOINT ["zilant"]
