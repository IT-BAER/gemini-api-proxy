FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV PORT=8080
EXPOSE 8080

# Keep token persistent
ENV TOKEN_FILE=/data/google_token.json

CMD ["python", "app.py"]
