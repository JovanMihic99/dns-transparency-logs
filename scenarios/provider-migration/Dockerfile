FROM python:3.12.12-alpine3.22

WORKDIR /app

COPY requirements.txt ./
RUN apk add --no-cache unbound
RUN pip install --no-cache-dir --requirement requirements.txt

COPY migration.py ./

ENTRYPOINT ["python", "/app/migration.py"]
