"""GitHub アクセストークンなど機微情報を DB に永続保存する際の暗号化ヘルパー。

Issue #227: ユーザーごとの Slack Webhook 登録に伴い、ログイン時にしか使って
いなかった GitHub OAuth アクセストークンを DB へ永続保存する必要が生じた
（登録済みの各ユーザーのリポジトリを定期的に再スキャンするため）。トークンを
平文で DB に保存すると、DB 漏洩時に複数ユーザーの GitHub アクセス権限が
まとめて漏れるリスクがあるため、`cryptography`（既存の依存パッケージ、
Fernet: AES128-CBC + HMAC の対称暗号）で暗号化してから保存する。
"""
import logging

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger(__name__)


def encrypt_token(plaintext: str) -> str:
    """トークンを暗号化する。`TOKEN_ENCRYPTION_KEY` 未設定時は例外を送出する
    （機微情報を誤って平文保存してしまう事故を防ぐため、Fail Fast）。
    """
    if not settings.TOKEN_ENCRYPTION_KEY:
        raise RuntimeError(
            "TOKEN_ENCRYPTION_KEY is not configured; cannot encrypt GitHub access token.",
        )
    fernet = Fernet(settings.TOKEN_ENCRYPTION_KEY.encode("utf-8"))
    return fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_token(ciphertext: str) -> str | None:
    """暗号化済みトークンを復号する。鍵不一致・破損等の場合は None を返す
    （呼び出し元でそのユーザーの定期実行をスキップできるようにするため、
    例外を送出せずソフトフェイルにする）。
    """
    if not settings.TOKEN_ENCRYPTION_KEY:
        return None
    fernet = Fernet(settings.TOKEN_ENCRYPTION_KEY.encode("utf-8"))
    try:
        return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        logger.warning("Failed to decrypt stored GitHub access token: %s", exc)
        return None
