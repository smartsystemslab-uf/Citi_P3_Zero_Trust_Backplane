FROM python:3.12-slim
WORKDIR /app
ENV PYTHONPATH=/app/src
ENV ZT_PROJECT_ROOT=/app
COPY . /app
RUN pip install --no-cache-dir .
RUN useradd --system --uid 10001 ztpdp && chown -R ztpdp:ztpdp /app/runtime
USER ztpdp
EXPOSE 8080
CMD ["uvicorn", "zt_backplane.pdp_service:app", "--host", "0.0.0.0", "--port", "8080"]
