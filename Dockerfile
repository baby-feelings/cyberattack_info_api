# OCI Ampere A1（aarch64）を含む多アーキテクチャに対応する軽量イメージ
# （crypto_forecast/backend/Dockerfile と同じベースイメージパターン）
FROM python:3.11-slim

WORKDIR /app

# psycopg2-binary 等のビルドに備えて最小限のビルドツールを用意。curl は gitleaks
# バイナリのダウンロードに使う
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# gitleaks（CODESCAN のシークレット検知、Issue #219）: Go 製バイナリのため pip では
# 導入できず、GitHub Releases から本番環境（OCI Ampere A1 = Linux ARM64）向けの
# プリビルドバイナリを取得して配置する。latest タグは使わずバージョンを固定する
# （https://github.com/gitleaks/gitleaks/releases）。バージョンを上げる場合は
# https://api.github.com/repos/gitleaks/gitleaks/releases/latest で最新版を確認し、
# このARGを更新すること
ARG GITLEAKS_VERSION=8.30.1
RUN curl -fsSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz" \
    -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

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
