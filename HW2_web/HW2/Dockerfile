FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home app
COPY proxy ./proxy
COPY tools ./tools
COPY tests ./tests
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "proxy.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers", "--no-access-log", "--limit-concurrency", "100"]
