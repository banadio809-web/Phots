FROM python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp/phots-home \
    TMPDIR=/tmp/phots-tmp

WORKDIR /app

COPY requirements-container.txt ./
RUN pip install --no-cache-dir --requirement requirements-container.txt \
    && groupadd --system --gid 10001 phots \
    && useradd --system --uid 10001 --gid phots --home-dir /tmp/phots-home phots \
    && mkdir -p /output /tmp/phots-home /tmp/phots-tmp \
    && chown -R phots:phots /output /tmp/phots-home /tmp/phots-tmp

COPY --chown=phots:phots scanner.py ai_triage.py scope_filter.py supabase_store.py ./
COPY --chown=phots:phots rules ./rules

USER 10001:10001
ENTRYPOINT ["python", "/app/scanner.py"]
