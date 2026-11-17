FROM python:3.12.10-slim AS python-base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/broker
ARG PYTHON_PACKAGE_INDEX=https://pypi.org/simple
RUN groupadd --gid 10001 broker && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent broker
COPY requirements.txt .
RUN PIP_INDEX_URL="${PYTHON_PACKAGE_INDEX}" pip install --no-cache-dir --timeout=120 --retries=10 -r requirements.txt

FROM python-base AS runtime
RUN mkdir -p /data && chown 10001:10001 /data
COPY app ./app
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python-base AS test
COPY requirements-test.txt .
RUN PIP_INDEX_URL="${PYTHON_PACKAGE_INDEX}" pip install --no-cache-dir --timeout=120 --retries=10 -r requirements-test.txt && mkdir -p /tmp/pytest-cache && chown -R 10001:10001 /tmp/pytest-cache
COPY app ./app
COPY tests ./tests
COPY pytest.ini .
USER 10001:10001
ENV TMPDIR=/tmp
CMD ["pytest", "-q", "-o", "cache_dir=/tmp/pytest-cache"]
