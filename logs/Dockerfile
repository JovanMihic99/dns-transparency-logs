FROM python:3.14-slim

# Python configuration
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV LOKEY_DATA_DIR=/app/data

# Host UID/GID are passed during the build
ARG UID=1000
ARG GID=1000

# Create a non-root application user
RUN groupadd --gid ${GID} lokey && \
    useradd --uid ${UID} \
             --gid ${GID} \
             --create-home \
             --shell /usr/sbin/nologin lokey

# Application directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app.py verify.py ./
COPY lokey/ ./lokey/
COPY templates/ ./templates/
COPY static/ ./static/


# Create data directory
RUN mkdir -p /app/data && \
    chown -R lokey:lokey /app

# Run as non-root
USER lokey

# Flask application port
EXPOSE 5000

# Start application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
