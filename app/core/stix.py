"""STIX 2.1変換の横断的共通処理（KEV/OSV/JVN共通、Issue #134のOSV/JVN拡張）。

複数の脆弱性DB・APIを跨いで情報を収集する際、標準フォーマットの欠如が
相互運用の障害となっている問題に対応するため、KEV向けに導入したSTIX 2.1変換の
共通部分（オブジェクトIDの名前空間・タイムスタンプ変換）をドメイン非依存の
形でここに切り出す。KEV固有のロジック（app.kev.stix）はこれをimportして使う。

**既存のオブジェクトID生成結果は一切変わらない**（値は移動前と同一）。
"""
import uuid
from datetime import datetime, timezone

# STIXオブジェクトIDを安定させるための名前空間UUID（uuid5用、DNS名前空間の
# 標準UUID）。同じ自然キー（CVE ID等）に対して常に同じIDを生成することで、
# TAXIIクライアント側の差分取得（added_after等）や重複排除が正しく機能する。
#
# 元は app.kev.stix._STIX_ID_NAMESPACE として定義されていた値をそのまま移動した
# （既存のKEV向けオブジェクトID生成結果に影響を与えないため、値は変更しない）。
STIX_ID_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def stix_timestamp(dt: datetime) -> str:
    """STIXタイムスタンプ形式（RFC3339、ミリ秒・Z終端）に変換する。

    元は app.kev.stix._stix_timestamp として定義されていたロジックをそのまま
    移動した（振る舞いは変更しない）。
    """
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt_utc.microsecond // 1000:03d}Z"
