FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 3001

CMD ["uvicorn", "socket_broadcast_gateway:app", "--host", "0.0.0.0", "--port", "3001"]