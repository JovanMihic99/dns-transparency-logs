FROM python:3.12.12-alpine3.22
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt
COPY ds_removal.py ./
ENTRYPOINT ["python", "/app/ds_removal.py"]
