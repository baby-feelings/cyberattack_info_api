"""公開サイトの点検（TLS 証明書・セキュリティヘッダー・露出ファイル・DNS・Firestore）。

判定は純粋な関数（`evaluate_*`・`looks_like_*`）に分け、ネットワークに触れる処理（`check_tls`・
`resolve_host`・`probe_*`）は薄く保つ。いずれも **非侵入**
（GET のみ・少数のパス・リダイレクトを辿らない）。

【SSRF 対策】点検の対象 URL は、リポジトリの情報や設定から来るため、https 以外・
ホスト名が内部アドレス
（プライベート・ループバック・リンクローカル等）に解決されるものは、点検しない（`is_safe_target`）。
"""
import ipaddress
import logging
import socket
import ssl
import time
from collections.abc import Mapping
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

ERROR = "ERROR"
WARNING = "WARNING"
INFO = "INFO"

_TIMEOUT = 8.0
# 応答の本文を読む上限（バイト）。悪意あるサイトが、巨大な応答を返しても、メモリを使い切らない
_MAX_BODY_BYTES = 65_536
# 1サイトの点検に使う時間の上限（秒）。超えたら、残りの確認は行わない
_SITE_BUDGET_SECONDS = 40.0
# 証明書の期限の通知しきい値（日）
TLS_WARN_DAYS = 30
TLS_ERROR_DAYS = 7

# 露出を確認するパス: (パス, ルール名, 内容の判定)。GET のみ・少数に限る
_EXPOSURE_PATHS: tuple[tuple[str, str], ...] = (
    ("/.env", "exposed-env"),
    ("/.git/HEAD", "exposed-git"),
    ("/.git/config", "exposed-git"),
    ("/firebase.json", "exposed-firebase-json"),
    ("/backup.zip", "exposed-backup"),
)

# 乗っ取りが可能になった（サービス側のリソースが無い）ときに表示される、典型の文言
_TAKEOVER_FINGERPRINTS = (
    "there isn't a github pages site here",
    "nosuchbucket",
    "no such app",
    "the specified bucket does not exist",
    "project not found",
)


def _finding(rule: str, severity: str, message: str) -> dict[str, str]:
    return {"rule": rule, "severity": severity, "message": message}


# ---------------------------------------------------------------------------
# 対象の安全確認（SSRF 対策）
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> list[str] | None:
    """ホスト名を IP アドレスに解決する（解決できなければ None）。"""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return sorted({str(info[4][0]) for info in infos})
    except (socket.gaierror, UnicodeError):
        return None


def is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def is_safe_target(url: str) -> bool:
    """点検してよい URL か（https・ホスト名あり・すべてのアドレスが公開アドレス）。"""
    parts = urlsplit(url)
    host = parts.hostname
    if parts.scheme != "https" or not host:
        return False
    try:
        ipaddress.ip_address(host)
        return False                       # IP アドレスの直接指定は、対象外
    except ValueError:
        pass
    addresses = resolve_host(host)
    if not addresses:
        return False
    return all(is_public_ip(a) for a in addresses)


# ---------------------------------------------------------------------------
# TLS 証明書
# ---------------------------------------------------------------------------

def check_tls(host: str, port: int = 443) -> tuple[int | None, list[dict[str, str]]]:
    """証明書の残り日数と、問題を返す。検証に失敗（期限切れ・不一致等）したら、ERROR を返す。"""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock, \
                context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        message = f"TLS 証明書を検証できません: {exc.verify_message}"
        return None, [_finding("tls-invalid", ERROR, message)]
    except (OSError, ssl.SSLError) as exc:
        return None, [_finding("tls-unreachable", WARNING, f"TLS で接続できません: {exc}")]
    days_left = int((ssl.cert_time_to_seconds(str(cert["notAfter"])) - time.time()) // 86400)
    return days_left, evaluate_tls(days_left)


def evaluate_tls(days_left: int) -> list[dict[str, str]]:
    """証明書の残り日数から、問題を判定する。"""
    if days_left < 0:
        message = f"TLS 証明書の期限が切れています（{-days_left}日前）"
        return [_finding("tls-expired", ERROR, message)]
    if days_left <= TLS_ERROR_DAYS:
        return [_finding("tls-expiring", ERROR, f"TLS 証明書の期限が、あと{days_left}日です")]
    if days_left <= TLS_WARN_DAYS:
        return [_finding("tls-expiring", WARNING, f"TLS 証明書の期限が、あと{days_left}日です")]
    return []


# ---------------------------------------------------------------------------
# セキュリティヘッダー
# ---------------------------------------------------------------------------

def evaluate_headers(headers: Mapping[str, str]) -> list[dict[str, str]]:
    """応答ヘッダーから、不足しているセキュリティヘッダーを判定する。"""
    lowered = {k.lower(): v for k, v in headers.items()}
    csp = lowered.get("content-security-policy", "")
    findings = []
    if not csp:
        findings.append(_finding(
            "missing-csp", WARNING,
            "Content-Security-Policy がありません（XSS の被害を抑えられません）",
        ))
    if not lowered.get("strict-transport-security"):
        findings.append(_finding(
            "missing-hsts", WARNING,
            "Strict-Transport-Security がありません（https への固定ができません）",
        ))
    if lowered.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_finding(
            "missing-nosniff", INFO, "X-Content-Type-Options: nosniff がありません",
        ))
    # クリックジャッキング対策は、X-Frame-Options か、CSP の frame-ancestors のどちらか
    if not lowered.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        findings.append(_finding(
            "missing-frame-protection", INFO,
            "X-Frame-Options（または frame-ancestors）がありません",
        ))
    if not lowered.get("referrer-policy"):
        findings.append(_finding("missing-referrer-policy", INFO, "Referrer-Policy がありません"))
    return findings


# ---------------------------------------------------------------------------
# 露出ファイル
# ---------------------------------------------------------------------------

def looks_like_exposure(rule: str, content_type: str, body: str) -> bool:
    """応答の内容が、本当にそのファイルか。

    SPA の「何でも index.html を返す」挙動を、誤検知しない。
    """
    head = body.lstrip()[:2000]
    is_html = "html" in content_type.lower() or head.lower().startswith(("<!doctype", "<html"))
    if rule == "exposed-env":
        lines = [ln for ln in head.splitlines() if ln.strip() and not ln.startswith("#")]
        return not is_html and bool(lines) and all(
            "=" in ln and ln.split("=", 1)[0].replace("_", "").isalnum() for ln in lines[:5]
        )
    if rule == "exposed-git":
        return not is_html and (head.startswith("ref:") or "[core]" in head)
    if rule == "exposed-firebase-json":
        return not is_html and '"hosting"' in head
    if rule == "exposed-backup":
        return "zip" in content_type.lower() or "octet-stream" in content_type.lower()
    return False


def fetch_limited(
    client: httpx.Client, url: str, *, read_body: bool = True, **params: str | int,
) -> tuple[int, httpx.Headers, str]:
    """GET して (ステータス, ヘッダー, 本文) を返す。本文は、`_MAX_BODY_BYTES` までしか読まない。

    `client.get` は、本文をすべてメモリに読み込む。ストリームで受け、上限で打ち切る。
    `read_body=False` のときは、本文を読まない（ステータスとヘッダーだけで判定できるとき）。
    """
    with client.stream("GET", url, params=params or None) as response:
        if not read_body:
            return response.status_code, response.headers, ""
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= _MAX_BODY_BYTES:
                break
        text = b"".join(chunks)[:_MAX_BODY_BYTES].decode("utf-8", errors="replace")
        return response.status_code, response.headers, text


def probe_exposure(
    client: httpx.Client, base_url: str, deadline: float | None = None,
) -> list[dict[str, str]]:
    """露出してはいけないファイルを、GET で確認する（リダイレクトは辿らない）。"""
    findings: list[dict[str, str]] = []
    reported: set[str] = set()
    for path, rule in _EXPOSURE_PATHS:
        if rule in reported:
            continue
        if deadline is not None and time.monotonic() > deadline:
            break
        try:
            # バックアップ（zip）は、種類（Content-Type）だけで判定できるため、本文は読まない
            status, headers, text = fetch_limited(
                client, f"{base_url}{path}", read_body=rule != "exposed-backup",
            )
        except httpx.HTTPError:
            continue
        if status == 200 and looks_like_exposure(rule, headers.get("content-type", ""), text):
            reported.add(rule)
            findings.append(_finding(
                rule, ERROR,
                f"`{path}` が、誰でも取得できます（内容は記録していません）。直ちに公開を止め、"
                "含まれていた認証情報を、無効化・再発行してください",
            ))
    return findings


# ---------------------------------------------------------------------------
# DNS（宙ぶらりん）・Firestore
# ---------------------------------------------------------------------------

def evaluate_takeover(
    host: str, addresses: list[str] | None, status: int | None, body: str,
) -> list[dict[str, str]]:
    """名前が解決できない、またはサービス側のリソースが無い表示のとき、乗っ取りの危険として判定する。"""
    if addresses is None:
        return [_finding(
            "dangling-dns", ERROR,
            f"`{host}` の名前が解決できません。DNS のレコードが残っているなら、削除してください"
            "（サブドメインの乗っ取りの危険）",
        )]
    lowered = body.lower()
    if status in (404, 410, 200) and any(fp in lowered for fp in _TAKEOVER_FINGERPRINTS):
        return [_finding(
            "subdomain-takeover", ERROR,
            f"`{host}` は、サービス側のリソースが無い表示です。"
            "第三者に、このドメインを使われる危険があります",
        )]
    return []


def probe_firestore(client: httpx.Client, project_id: str) -> list[dict[str, str]]:
    """Firestore の REST API を、認証なしで読めるか。読めるなら、意図した公開範囲か確認を促す。"""
    url = (
        f"https://firestore.googleapis.com/v1/projects/{project_id}"
        "/databases/(default)/documents"
    )
    try:
        status, _, _ = fetch_limited(client, url, read_body=False, pageSize=1)
    except httpx.HTTPError:
        return []
    if status == 200:
        return [_finding(
            "firestore-public-read", WARNING,
            f"Firestore（{project_id}）を、認証なしで読めます。意図した公開範囲か確認してください"
            "（firestore.rules を、認証と所有者の確認を条件にする）",
        )]
    return []


def probe_site(url: str, project_id: str | None = None) -> tuple[int | None, list[dict[str, str]]]:
    """1サイトを点検する。(TLS の残り日数, 問題の一覧) を返す。"""
    parts = urlsplit(url)
    host = parts.hostname or ""
    base = f"https://{parts.netloc}"
    findings: list[dict[str, str]] = []
    deadline = time.monotonic() + _SITE_BUDGET_SECONDS

    addresses = resolve_host(host)
    days_left: int | None = None
    tls_findings: list[dict[str, str]] = []
    if addresses is not None:
        days_left, tls_findings = check_tls(host, parts.port or 443)
    findings += tls_findings

    status: int | None = None
    body = ""
    if addresses is not None:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False,
                          headers={"User-Agent": "cyberattack-info-api-monitor/1.0"}) as client:
            try:
                status, headers, body = fetch_limited(client, base + "/")
                findings += evaluate_headers(headers)
            except httpx.HTTPError as exc:
                findings.append(_finding("unreachable", WARNING, f"サイトに接続できません: {exc}"))
            # 露出の判定は、内容を見る（何でも index.html を返す SPA を、誤検知しない）
            findings += probe_exposure(client, base, deadline)
            if project_id:
                findings += probe_firestore(client, project_id)
    findings += evaluate_takeover(host, addresses, status, body)
    return days_left, findings
