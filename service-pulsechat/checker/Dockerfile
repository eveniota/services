FROM python:3.11-slim
WORKDIR /checker

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src
ENV SERVICE_PORT=8001
EXPOSE 8001

CMD ["uvicorn", "src.checker:app", "--host", "0.0.0.0", "--port", "8001", "--factory"]
