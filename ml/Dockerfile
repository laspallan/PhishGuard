# Image for the snapshot collector and the daily collector (build context: repo root).
# Only this container may fetch phishing pages: PHISHGUARD_IN_SNAPSHOT_CONTAINER=1 is set here
# and nowhere else, and phishguard_ml refuses to take snapshots without it.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHISHGUARD_DATA_DIR=/data \
    PHISHGUARD_IN_SNAPSHOT_CONTAINER=1

WORKDIR /app
COPY backend/pyproject.toml backend/
COPY backend/phishguard backend/phishguard
COPY ml/pyproject.toml ml/
COPY ml/phishguard_ml ml/phishguard_ml
RUN pip install --no-cache-dir ./backend ./ml

RUN useradd --create-home collector
USER collector

ENTRYPOINT ["python", "-m", "phishguard_ml"]
