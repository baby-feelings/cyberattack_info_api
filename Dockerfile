# OCI Ampere A1（aarch64）を含む多アーキテクチャに対応する軽量イメージ
# （crypto_forecast/backend/Dockerfile と同じベースイメージパターン）
FROM python:3.11-slim

WORKDIR /app

# psycopg2-binary 等のビルドに備えて最小限のビルドツールを用意
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 依存パッケージのインストール（レイヤーキャッシュを効かせるため先にコピー）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーション本体
COPY app/ ./app/

# Alembicマイグレーション定義（起動時に app.core.migrate で適用する）
COPY alembic.ini .
COPY alembic/ ./alembic/

ENV ENVIRONMENT=production
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Render の Start Command と同じ順序（migrate → uvicorn）
CMD ["sh", "-c", "python -m app.core.migrate && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
