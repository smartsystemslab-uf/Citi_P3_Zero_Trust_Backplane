FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY config ./config
COPY policy_store ./policy_store
RUN mkdir -p /app/runtime
ENV PYTHONPATH=/app/src
EXPOSE 8080
CMD ["uvicorn", "zt_backplane.pdp_service:app", "--host", "0.0.0.0", "--port", "8080"]
