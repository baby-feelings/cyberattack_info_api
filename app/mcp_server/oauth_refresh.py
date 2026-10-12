"""OAuth 2.1 リフレッシュトークンの保存層（ローテーション・盗用検知・失効。Issue #303）。

- 発行: 最初の認可で新しい系統（`family_id`）を作り、以降は交換のたびに
  同じ系統へ新しいトークンを連ねる
- ローテーション: 使うたびに新しいトークンへ交換し、元のトークンは `used_at` を付けて残す。
  交換は条件付きの UPDATE（件数で判定）なので、同じトークンを同時に2回使っても片方だけが成功する
- 盗用検知: 使用済みのトークンが再び提示されたら、同じ系統をすべて失効する
  （正規のクライアントと攻撃者の両方が使えなくなり、再認可が必要になる）
- 保存: トークン本体は保存せず SHA-256 のみ。有効期間は発行（交換）から 30 日
"""
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.auth.mcp_token_store import as_utc
from app.auth.models import OAuthRefreshToken

# リフレッシュトークンの有効期間（交換のたびに延びる）
REFRESH_TTL = timedelta(days=30)

# 失効・期限切れから、この日数を過ぎた行は発行時に掃除する（盗用検知のため、使用済みも一定期間残す）
_RETENTION = timedelta(days=7)


def _now() -> datetime:
    return datetime.now(UTC)


def hash_token(token: str) -> str:
    """トークンの SHA-256（保存・照合用。十分なエントロピーのため塩は不要）。"""
    return hashlib.sha256(token.encode()).hexdigest()


def issue(
    db: Session, client_id: str, username: str, scope: str, resource: str | None,
    family_id: str | None = None, now: datetime | None = None,
) -> str:
    """リフレッシュトークンを発行し、平文を返す（保存はハッシュのみ）。

    `family_id` が None なら新しい系統（最初の認可）、指定があればローテーションで同じ系統に連ねる。
    """
    now = now or _now()
    purge_stale(db, now)
    token = secrets.token_urlsafe(48)
    db.add(OAuthRefreshToken(
        token_hash=hash_token(token),
        family_id=family_id or str(uuid.uuid4()),
        client_id=client_id,
        username=username,
        scope=scope,
        resource=resource,
        created_at=now,
        expires_at=now + REFRESH_TTL,
    ))
    db.commit()
    return token


def purge_stale(db: Session, now: datetime | None = None) -> None:
    """期限切れ・失効から一定期間（_RETENTION）を過ぎた行を削除する。"""
    cutoff = (now or _now()) - _RETENTION
    # synchronize_session=False: SQLite は tz 情報を落とすため、Python 側での比較評価を避ける
    db.execute(
        delete(OAuthRefreshToken).where(
            (OAuthRefreshToken.expires_at < cutoff) | (OAuthRefreshToken.revoked_at < cutoff),
        ).execution_options(synchronize_session=False),
    )
    db.commit()


def find_usable(
    db: Session, token: str, client_id: str, now: datetime | None = None,
) -> OAuthRefreshToken | None:
    """提示されたトークンが、そのクライアントの有効なものなら行を返す。

    使用済みのトークンが提示されたら盗用の疑いとして系統をすべて失効し、None を返す。
    別クライアントのトークン・期限切れ・失効済み・未登録も None。
    """
    now = now or _now()
    row = db.get(OAuthRefreshToken, hash_token(token))
    if row is None or row.client_id != client_id:
        return None
    if row.used_at is not None and row.revoked_at is None:
        revoke_family(db, row.family_id, now)  # 盗用の疑い（使用済みの再提示）
        return None
    if row.revoked_at is not None or as_utc(row.expires_at) <= now:
        return None
    return row


def rotate(db: Session, row: OAuthRefreshToken, now: datetime | None = None) -> bool:
    """トークンを使用済みにする。成功したら True（条件付き UPDATE の件数で判定）。

    同じトークンを同時に2回交換しようとしても、成功するのは片方だけ。
    """
    result = db.execute(
        update(OAuthRefreshToken)
        .where(
            OAuthRefreshToken.token_hash == row.token_hash,
            OAuthRefreshToken.used_at.is_(None),
            OAuthRefreshToken.revoked_at.is_(None),
        )
        .values(used_at=now or _now())
        .execution_options(synchronize_session=False),
    )
    db.commit()
    return result.rowcount == 1  # type: ignore[attr-defined]


def revoke_family(db: Session, family_id: str, now: datetime | None = None) -> None:
    """同じ系統のリフレッシュトークンをすべて失効する。"""
    db.execute(
        update(OAuthRefreshToken)
        .where(OAuthRefreshToken.family_id == family_id, OAuthRefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or _now())
        .execution_options(synchronize_session=False),
    )
    db.commit()


def revoke_client_grants(
    db: Session, username: str, client_id: str, now: datetime | None = None,
) -> None:
    """本人がそのクライアントに与えたリフレッシュトークンを、すべて失効する（接続解除）。"""
    db.execute(
        update(OAuthRefreshToken)
        .where(
            OAuthRefreshToken.username == username,
            OAuthRefreshToken.client_id == client_id,
            OAuthRefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now or _now())
        .execution_options(synchronize_session=False),
    )
    db.commit()
