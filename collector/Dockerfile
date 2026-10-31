FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Host UID/GID, same pattern as logs/Dockerfile
ARG UID=1000
ARG GID=1000
RUN groupadd --gid ${GID} lokey && \
    useradd --uid ${UID} --gid ${GID} --create-home --shell /usr/sbin/nologin lokey

WORKDIR /app

COPY collector/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY collector/ ./collector/

RUN mkdir -p /app/data && chown -R lokey:lokey /app
USER lokey

# Settings come from LOKEY_* env vars (see docker-compose.yml); args = domains to watch
ENTRYPOINT ["python", "-m", "collector.run"]
CMD ["victim.test"]