FROM python:3.12.12-alpine3.22

WORKDIR /app

COPY cds-rollover/requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY cds-rollover/cds_sync.py ./

ENTRYPOINT ["python", "/app/cds_sync.py"]
CMD ["sync"]
