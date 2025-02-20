FROM python:3.12-alpine

WORKDIR /app

COPY exporter.py .

# Install curl for healthcheck and create directories/user
RUN apk add --no-cache curl && \
    mkdir -p /app/temp && \
    # Create non-root user
    adduser -D exporter && \
    chown -R exporter:exporter /app

USER exporter

ENV PYTHONUNBUFFERED=1

EXPOSE 9876

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9876/health || exit 1

ENTRYPOINT ["python3", "exporter.py"] 