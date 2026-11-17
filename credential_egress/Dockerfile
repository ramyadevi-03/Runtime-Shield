FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.135.2 uvicorn==0.42.0 httpx==0.28.1
COPY app.py ./app.py
USER 10001:10001
EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
