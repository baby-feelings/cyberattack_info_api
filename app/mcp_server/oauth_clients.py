"""OAuth 動的クライアント登録の保存層と、登録内容の検証（Issue #303）。

登録は誰でも呼べる（MCP 標準のクライアントはログイン前に `/register` を呼ぶ）ため、
「登録だけではデータは見えない」ことを前提に、悪用対策として次を課す。

- redirect_uri は https、または http のループバック（localhost / 127.0.0.1 / ::1）のみ
- 直近 1 時間の登録数に上限（`MAX_REGISTRATIONS_PER_HOUR`）、総数にも上限（`MAX_CLIENTS`）
- 一度も使われないまま一定期間を過ぎた登録は、登録時に掃除する
"""
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import OAuthClientInformationFull
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.mcp_server.models import OAuthClient

# 1 時間あたりの登録数の上限（全体。登録元 IP は SDK のハンドラーから見えないため全体で絞る）
MAX_REGISTRATIONS_PER_HOUR = 60

# 保持するクライアントの総数の上限
MAX_CLIENTS = 1000

# 一度も使われないクライアントを掃除するまでの日数
UNUSED_RETENTION = timedelta(days=30)

# 1 クライアントが登録できる redirect_uri の数
MAX_REDIRECT_URIS = 5

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _now() -> datetime:
    return datetime.now(UTC)


def validate_redirect_uri(uri: str) -> None:
    """redirect_uri を検証する。不正なら RegistrationError。"""
    parts = urlsplit(uri)
    if parts.fragment:
        raise RegistrationError("invalid_redirect_uri", "redirect_uri must not contain a fragment")
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS:
        return
    raise RegistrationError(
        "invalid_redirect_uri",
        "redirect_uri must be https, or http on localhost / 127.0.0.1 / ::1",
    )


def validate_registration(client: OAuthClientInformationFull) -> None:
    """登録内容を検証する（redirect_uri の数・形式）。"""
    uris = [str(u) for u in (client.redirect_uris or [])]
    if not uris or len(uris) > MAX_REDIRECT_URIS:
        raise RegistrationError(
            "invalid_redirect_uri", f"between 1 and {MAX_REDIRECT_URIS} redirect_uris are required",
        )
    for uri in uris:
        validate_redirect_uri(uri)


def purge_unused_clients(db: Session, now: datetime | None = None) -> int:
    """一度も使われず、登録から UNUSED_RETENTION を過ぎたクライアントを削除する。"""
    cutoff = (now or _now()) - UNUSED_RETENTION
    stale = (
        db.execute(
            select(OAuthClient.client_id).where(
                OAuthClient.last_used_at.is_(None), OAuthClient.created_at < cutoff,
            )
        )
        .scalars()
        .all()
    )
    if stale:
        db.execute(delete(OAuthClient).where(OAuthClient.client_id.in_(stale)))
        db.commit()
    return len(stale)


def save_client(
    db: Session, client: OAuthClientInformationFull, now: datetime | None = None,
) -> None:
    """クライアントを保存する。上限超過なら RegistrationError（保存しない）。"""
    now = now or _now()
    validate_registration(client)
    purge_unused_clients(db, now)

    recent = db.scalar(
        select(func.count())
        .select_from(OAuthClient)
        .where(OAuthClient.created_at > now - timedelta(hours=1))
    )
    total = db.scalar(select(func.count()).select_from(OAuthClient))
    if (recent or 0) >= MAX_REGISTRATIONS_PER_HOUR or (total or 0) >= MAX_CLIENTS:
        raise RegistrationError(
            "invalid_client_metadata", "too many client registrations; try again later",
        )

    assert client.client_id is not None  # noqa: S101 - SDK のハンドラーが必ず採番する
    db.add(OAuthClient(
        client_id=client.client_id, client_info_json=client.model_dump_json(), created_at=now,
    ))
    db.commit()


def load_client(db: Session, client_id: str) -> OAuthClientInformationFull | None:
    """クライアントを取得する。未登録なら None。"""
    row = db.get(OAuthClient, client_id)
    if row is None:
        return None
    return OAuthClientInformationFull.model_validate_json(row.client_info_json)


def touch_client(db: Session, client_id: str, now: datetime | None = None) -> None:
    """クライアントが使われたことを記録する（未使用の掃除対象から外す）。"""
    row = db.get(OAuthClient, client_id)
    if row is not None:
        row.last_used_at = now or _now()
        db.commit()
