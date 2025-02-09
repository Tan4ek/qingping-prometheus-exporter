FROM python:3.12-alpine

WORKDIR /app

COPY exporter.py .

# Create temp directory for token cache
RUN mkdir -p /app/temp && \
    # Create non-root user
    adduser -D exporter && \
    chown -R exporter:exporter /app

USER exporter

ENV PYTHONUNBUFFERED=1

EXPOSE 9876

ENTRYPOINT ["python3", "exporter.py"] 