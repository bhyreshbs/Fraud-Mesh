FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# lightgbm needs libgomp at runtime
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*

COPY api/requirements.txt api/requirements.txt
COPY engine/requirements.txt engine/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt -r engine/requirements.txt

COPY . .

EXPOSE 8000
CMD ["sh", "-c", "alembic -c api/db/alembic.ini upgrade head && uvicorn api.main:app --host 0.0.0.0 --port 8000"]
