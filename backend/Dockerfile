FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
# Production default: no --reload (dev-only auto-reload is added by
# docker-compose.override.yml for local development). This keeps the image safe
# to run as-is on a non-dev container/VM target (L3).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
