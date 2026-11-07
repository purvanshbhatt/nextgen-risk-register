FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NGRR_DATA_DIR=/app/data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY run.py .

EXPOSE 8000
VOLUME ["/app/data"]

CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8000"]
