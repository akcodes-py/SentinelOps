FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY policy.yaml policy.schema.json ./
COPY src ./src
COPY scripts ./scripts
ENV PYTHONPATH=/app/src SENTINEL_MODE=defended SENTINEL_DB_URL=sqlite:////app/data/sentinel.db
EXPOSE 8000
CMD ["uvicorn", "sentinelops.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
