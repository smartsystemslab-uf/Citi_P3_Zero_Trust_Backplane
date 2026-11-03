# The original citi_banking_backend service (from the staged MAS copy), with the backend's
# own pinned requirements.txt, plus the golden-data tool of this deployment.
#   docker build -f distributed_runtime/deploy/docker/backend.Dockerfile \
#       --build-context citi_mas=distributed_runtime/runtime/build/Citi_P3 -t citi-ztbp/backend:dev .
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=citi_mas citi_banking_backend/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && pip freeze > /opt/pip-freeze.txt
COPY --from=citi_mas citi_banking_backend /opt/citi/citi_banking_backend
COPY distributed_runtime/deploy/backend /opt/citi/backend_tools
# app/database.py creates <app>/data at import; the live DB is on the bankdata volume
RUN mkdir -p /opt/citi/citi_banking_backend/data && chown 20010:20010 /opt/citi/citi_banking_backend/data \
 && chmod -R a+rX /opt/citi
WORKDIR /opt/citi/citi_banking_backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "warning"]
