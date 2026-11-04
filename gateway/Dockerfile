FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY config.py imap_gateway.py ./

# Run as a non-root user; the state file lives in /app/state (mount a volume there).
RUN useradd --create-home gateway && mkdir -p /app/state && chown gateway /app/state
USER gateway
ENV PHISHGUARD_GATEWAY_STATE_FILE=/app/state/gateway_state.json
CMD ["python", "imap_gateway.py"]
