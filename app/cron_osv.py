"""OSV (Open Source Vulnerabilities) クローラーモジュール。

OSV REST API (https://api.osv.dev/v1/) を使い、各エコシステムの主要パッケージに
影響する脆弱性を取得して DB に Upsert する。
APScheduler から毎週呼び出される。
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import OsvVulnerability

logger = logging.getLogger(__name__)

# OSV REST API ベース URL
OSV_API_BASE = "https://api.osv.dev/v1"

# 1回の /v1/querybatch で送れる最大クエリ数
BATCH_SIZE = 1000

# エコシステムごとの主要パッケージ一覧（脆弱性監視対象）
POPULAR_PACKAGES: dict[str, list[str]] = {
    "PyPI": [
        "django", "flask", "fastapi", "requests", "cryptography",
        "pillow", "numpy", "pandas", "sqlalchemy", "aiohttp",
        "paramiko", "pyyaml", "urllib3", "certifi", "setuptools",
        "tornado", "gunicorn", "uvicorn", "httpx", "jinja2",
        "werkzeug", "celery", "redis", "pymongo", "psycopg2",
        "boto3", "twisted", "scrapy", "pyopenssl", "ansible",
        "tensorflow", "torch", "scikit-learn", "lxml", "beautifulsoup4",
        "pygments", "pydantic", "click", "rich", "pytest",
        "black", "mypy", "ruff", "httplib2", "stripe",
        "twilio", "sendgrid", "elasticsearch", "grpcio", "protobuf",
        "pyarrow", "scipy", "matplotlib", "jupyter", "notebook",
        "virtualenv", "poetry", "pipenv", "tox", "coverage",
    ],
    "npm": [
        "express", "lodash", "moment", "axios", "react",
        "webpack", "jquery", "typescript", "eslint", "prettier",
        "next", "gatsby", "angular", "vue", "nuxt",
        "helmet", "passport", "jsonwebtoken", "bcrypt", "mongoose",
        "sequelize", "typeorm", "knex", "socket.io", "nodemailer",
        "multer", "cors", "dotenv", "morgan", "compression",
        "body-parser", "cookie-parser", "uuid", "dayjs", "date-fns",
        "luxon", "underscore", "ramda", "redux", "rxjs",
        "graphql", "apollo-server", "fastify", "koa", "hapi",
        "tar", "minimatch", "glob", "semver", "debug",
        "chalk", "commander", "yargs", "inquirer", "ora",
    ],
    "Go": [
        "github.com/gin-gonic/gin",
        "github.com/gorilla/mux",
        "github.com/labstack/echo/v4",
        "github.com/go-chi/chi/v5",
        "gorm.io/gorm",
        "github.com/golang-jwt/jwt/v5",
        "github.com/go-redis/redis/v9",
        "github.com/spf13/viper",
        "go.uber.org/zap",
        "github.com/sirupsen/logrus",
        "github.com/google/uuid",
        "github.com/pkg/errors",
        "github.com/stretchr/testify",
        "github.com/jmoiron/sqlx",
        "golang.org/x/crypto",
        "golang.org/x/net",
        "golang.org/x/text",
        "github.com/aws/aws-sdk-go-v2",
        "google.golang.org/grpc",
        "github.com/prometheus/client_golang",
    ],
    "Maven": [
        "org.springframework:spring-core",
        "org.springframework.boot:spring-boot",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.apache.commons:commons-lang3",
        "commons-io:commons-io",
        "org.apache.logging.log4j:log4j-core",
        "ch.qos.logback:logback-classic",
        "org.hibernate:hibernate-core",
        "mysql:mysql-connector-java",
        "org.postgresql:postgresql",
        "com.google.guava:guava",
        "org.apache.httpcomponents:httpclient",
        "io.netty:netty-all",
        "org.bouncycastle:bcprov-jdk15on",
        "com.squareup.okhttp3:okhttp",
        "org.apache.struts:struts2-core",
        "org.springframework.security:spring-security-core",
        "com.h2database:h2",
        "org.xerial:sqlite-jdbc",
        "commons-collections:commons-collections",
    ],
    "RubyGems": [
        "rails", "activesupport", "activerecord", "actionpack",
        "devise", "nokogiri", "rack", "sinatra",
        "bundler", "puma", "unicorn", "sidekiq",
        "redis", "jwt", "bcrypt", "faraday",
        "rest-client", "httparty", "carrierwave", "paperclip",
    ],
    "NuGet": [
        "Newtonsoft.Json", "Microsoft.AspNetCore",
        "Microsoft.EntityFrameworkCore", "AutoMapper",
        "log4net", "NLog", "Serilog",
        "RestSharp", "Flurl.Http", "Polly",
        "MediatR", "Dapper", "StackExchange.Redis",
        "AWSSDK.Core", "Azure.Core",
        "System.Text.Json", "Microsoft.Data.SqlClient",
        "Npgsql", "MySql.Data", "MongoDB.Driver",
    ],
    "crates.io": [
        "serde", "tokio", "reqwest", "actix-web",
        "hyper", "axum", "warp", "rocket",
        "diesel", "sqlx", "redis", "openssl",
        "ring", "rustls", "crossbeam", "rayon",
        "clap", "log", "tracing", "anyhow",
    ],
    "Packagist": [
        "laravel/framework", "symfony/symfony",
        "guzzlehttp/guzzle", "monolog/monolog",
        "doctrine/orm", "twig/twig",
        "predis/predis", "nesbot/carbon",
        "league/flysystem", "phpmailer/phpmailer",
        "aws/aws-sdk-php", "stripe/stripe-php",
        "intervention/image", "spatie/laravel-permission",
        "typo3/cms-core", "drupal/core",
    ],
    "Hex": [
        "phoenix", "ecto", "plug", "cowboy",
        "ex_aws", "jason", "poison", "httpoison",
        "guardian", "comeonin", "bcrypt_elixir",
        "telemetry", "oban", "broadway",
    ],
}

# 後方互換: GCS ベースのクローラーと同じエコシステム名リスト
TARGET_ECOSYSTEMS = list(POPULAR_PACKAGES.keys())


def _parse_severity(vuln: dict[str, Any]) -> tuple[str | None, float | None]:
    """OSV エントリから重要度ラベルと CVSS スコアを抽出する。

    優先順位:
    1. database_specific.severity（GitHub Advisory Database が付与する文字列）
    2. database_specific.cvss.score（数値スコア）
    3. severity[].score が数値の場合

    Returns:
        (severity_label, cvss_score) のタプル
    """
    db_specific = vuln.get("database_specific", {}) or {}

    # 1. database_specific.severity（CRITICAL/HIGH/MEDIUM/LOW 文字列）
    sev_str = (db_specific.get("severity") or "").upper()
    if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cvss_score: float | None = None
        try:
            raw = (db_specific.get("cvss") or {}).get("score")
            if raw is not None:
                cvss_score = float(raw)
        except (TypeError, ValueError):
            pass
        return sev_str, cvss_score

    # 2. severity 配列に数値スコアが直接格納されている場合
    for sev in vuln.get("severity", []):
        try:
            score = float(sev.get("score", ""))
            if score >= 9.0:
                return "CRITICAL", score
            elif score >= 7.0:
                return "HIGH", score
            elif score >= 4.0:
                return "MEDIUM", score
            else:
                return "LOW", score
        except (TypeError, ValueError):
            pass

    return None, None


def _extract_fixed_versions(affected: dict[str, Any]) -> list[str]:
    """affected エントリの ranges から修正済みバージョン（fixed イベント）を抽出する。"""
    fixed: list[str] = []
    for rng in affected.get("ranges", []):
        for event in rng.get("events", []):
            if "fixed" in event:
                fixed.append(event["fixed"])
    return fixed


def _build_records(
    vuln: dict[str, Any], modified: datetime
) -> list[dict[str, Any]]:
    """OSV エントリを DB レコード辞書のリストに変換する。

    1つの脆弱性が複数パッケージに影響する場合は 1 レコード/パッケージ を生成する。
    """
    severity, cvss_score = _parse_severity(vuln)

    # 公開日時をパース（失敗時は modified で代替）
    published_str = vuln.get("published", "")
    try:
        published = datetime.fromisoformat(
            published_str.replace("Z", "+00:00")
        )
    except (ValueError, AttributeError):
        published = modified

    osv_id = vuln.get("id", "")
    aliases = [a for a in (vuln.get("aliases") or []) if a]
    # 参考リンクは最大 5 件に制限
    refs = [r["url"] for r in (vuln.get("references") or []) if r.get("url")][:5]
    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or None)

    records: list[dict[str, Any]] = []

    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {}) or {}
        pkg_name = (pkg.get("name") or "").strip()
        pkg_eco = (pkg.get("ecosystem") or "").strip()
        if not pkg_name or not pkg_eco:
            continue

        # 影響バージョンは最大 30 件に制限
        affected_versions = (affected.get("versions") or [])[:30]
        fixed_versions = _extract_fixed_versions(affected)

        records.append(
            {
                "osv_id": osv_id,
                "ecosystem": pkg_eco,
                "package_name": pkg_name,
                "aliases": aliases,
                "summary": summary,
                "details": details,
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_versions": affected_versions,
                "fixed_versions": fixed_versions,
                "references": refs,
                "published": published,
                "modified": modified,
            }
        )

    return records


def _query_packages_batch(
    packages: list[tuple[str, str]],  # [(package_name, ecosystem), ...]
) -> list[dict[str, Any]]:
    """/v1/querybatch で複数パッケージを一括クエリして {id, modified} リストを返す。

    querybatch は id と modified のみ返すため、詳細は別途 _fetch_vuln_by_id で取得する。

    Args:
        packages: (パッケージ名, エコシステム) のタプルリスト（最大 BATCH_SIZE 件）

    Returns:
        {"id": ..., "modified": ...} 辞書のリスト（重複 ID は除去済み）
    """
    if not packages:
        return []

    queries = [
        {"package": {"name": pkg, "ecosystem": eco}}
        for pkg, eco in packages
    ]

    with httpx.Client(timeout=60.0) as client:
        resp = client.post(
            f"{OSV_API_BASE}/querybatch",
            json={"queries": queries},
        )
        resp.raise_for_status()

    data = resp.json()
    # 脆弱性を ID でユニーク化（複数パッケージが同じ CVE に影響する場合の重複除去）
    seen: set[str] = set()
    refs: list[dict[str, Any]] = []
    for result in data.get("results", []):
        for v in result.get("vulns", []):
            vid = v.get("id", "")
            if vid and vid not in seen:
                seen.add(vid)
                refs.append({"id": vid, "modified": v.get("modified", "")})

    return refs


def _fetch_vuln_by_id(osv_id: str) -> dict[str, Any]:
    """GET /v1/vulns/{id} で脆弱性の完全な情報（affected・severity 等）を取得する。"""
    with httpx.Client(timeout=30.0) as client:
        resp = client.get(f"{OSV_API_BASE}/vulns/{osv_id}")
        resp.raise_for_status()
    return resp.json()


def _upsert_osv_records(
    db: Session, records: list[dict[str, Any]]
) -> tuple[int, int]:
    """OSV レコードを DB に Upsert する。

    (osv_id, ecosystem, package_name) をキーに INSERT または UPDATE する。
    modified が変化していない場合は UPDATE をスキップしてパフォーマンスを最適化する。

    Returns:
        (inserted_count, updated_count) のタプル
    """
    inserted = 0
    updated = 0

    for rec in records:
        existing = (
            db.query(OsvVulnerability)
            .filter(
                OsvVulnerability.osv_id == rec["osv_id"],
                OsvVulnerability.ecosystem == rec["ecosystem"],
                OsvVulnerability.package_name == rec["package_name"],
            )
            .first()
        )

        if existing is None:
            db.add(OsvVulnerability(**rec))
            inserted += 1
        elif existing.modified != rec["modified"]:
            # modified が更新されている場合のみ上書き
            for key, value in rec.items():
                setattr(existing, key, value)
            updated += 1

    db.commit()
    return inserted, updated


def fetch_and_store_osv() -> tuple[int, int]:
    """OSV クローラーのメインエントリポイント。

    OSV REST API を使い、各エコシステムの主要パッケージに影響する脆弱性を
    取得して DB に保存する。
    GCS zip ダウンロード方式と比べ、小さな HTTP リクエストで高速に完了する。
    APScheduler から定期呼び出しされる。
    """
    logger.info("=== OSV crawler started (API mode) ===")
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.OSV_DAYS)
    total_inserted = 0
    total_updated = 0

    db: Session = SessionLocal()
    try:
        for ecosystem, packages in POPULAR_PACKAGES.items():
            try:
                # Step 1: パッケージを BATCH_SIZE ずつ分割して {id, modified} を一括取得
                pkg_tuples = [(pkg, ecosystem) for pkg in packages]
                refs: list[dict[str, Any]] = []
                for i in range(0, len(pkg_tuples), BATCH_SIZE):
                    chunk = pkg_tuples[i: i + BATCH_SIZE]
                    refs.extend(_query_packages_batch(chunk))

                # Step 2: cutoff 以降に更新されたものに絞り込む
                recent_refs = []
                for ref in refs:
                    try:
                        modified = datetime.fromisoformat(
                            ref["modified"].replace("Z", "+00:00")
                        )
                        if modified >= cutoff:
                            recent_refs.append((ref["id"], modified))
                    except (ValueError, AttributeError, KeyError):
                        continue

                logger.info(
                    "OSV API [%s]: %d total vulns, %d recent (>= %s)",
                    ecosystem, len(refs), len(recent_refs), cutoff.date(),
                )

                # Step 3: 直近のものだけ GET /v1/vulns/{id} で完全情報を取得してレコード構築
                records: list[dict[str, Any]] = []
                for osv_id, modified in recent_refs:
                    try:
                        vuln = _fetch_vuln_by_id(osv_id)
                        records.extend(_build_records(vuln, modified))
                    except httpx.HTTPError as exc:
                        logger.warning("Failed to fetch %s: %s", osv_id, exc)

                ins, upd = _upsert_osv_records(db, records)
                total_inserted += ins
                total_updated += upd
                logger.info(
                    "OSV [%s] done: recent=%d records=%d inserted=%d updated=%d",
                    ecosystem, len(recent_refs), len(records), ins, upd,
                )

            except httpx.HTTPError as exc:
                logger.error("HTTP error for ecosystem %s: %s", ecosystem, exc)
            except Exception as exc:
                logger.error(
                    "Unexpected error for ecosystem %s: %s",
                    ecosystem, exc, exc_info=True,
                )
    finally:
        db.close()

    logger.info(
        "=== OSV crawler completed: inserted=%d, updated=%d ===",
        total_inserted, total_updated,
    )
    return total_inserted, total_updated
