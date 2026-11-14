FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY redteam ./redteam
COPY evals ./evals
COPY contracts ./contracts
COPY conftest.py .

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Railway injects $PORT. Shell form so it expands.
CMD uvicorn redteam.console.app:app --host 0.0.0.0 --port ${PORT:-8000}
