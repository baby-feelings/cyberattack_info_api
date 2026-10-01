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

# semgrep（CODESCAN の Semgrep 静的解析）: subprocess で呼ぶ外部 CLI のため、アプリの
# 依存とは別の専用 venv に隔離して導入し、PATH 上（/usr/local/bin）へ symlink する。
# semgrep は pyjwt~=2.13.0 を厳密にピン留めしており、同じ環境だとアプリの PyJWT を
# 修正済みの 2.15 以降に上げられないため。semgrep が使う PyJWT は脆弱性修正済みの版へ
# 上書きする（pip は依存の不整合を警告するが、semgrep CLI の動作には影響しない。
# semgrep 1.178.0 + PyJWT 2.15.1 で動作確認済み）
COPY semgrep-cli.txt .
RUN python -m venv /opt/semgrep-venv     && /opt/semgrep-venv/bin/pip install --no-cache-dir -r semgrep-cli.txt     && /opt/semgrep-venv/bin/pip install --no-cache-dir "PyJWT>=2.15.1"     && ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep     && semgrep --version

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
