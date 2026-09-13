"""KEV/OSV/JVNデータのTAXII 2.1配信（Issue #134、OSV/JVN拡張）。

複数の脆弱性DB・APIを跨いで情報を収集する際、標準フォーマットの欠如が
相互運用の障害となっている問題に対応する。MISP等の既存CTI共有基盤や
SIEM/TIPからの購読を想定した、最小構成のTAXII 2.1サーバー実装
（discovery・api-root・collections・objects）を提供する。

当初はKEV専用（app.kev.taxii）として実装したが、TAXIIはKEV固有ではなく
複数ドメインを跨ぐ配信機構であるため app.core.taxii へ移動し、コレクション
レジストリパターンでKEV/OSV/JVNの3ドメインに対応する。

対応範囲: 配信（読み取り専用）のみ。以下はスコープ外
（Issue #134本文もTAXIIを「将来的な拡張」と位置づけているため、
まずは購読可能な最小構成を提供する）:
- STIXオブジェクトのPUSH（書き込み）
- manifestエンドポイント（TAXII 2.1では任意〈MAY〉のため省略）
- TAXII固有の認証方式（OAuth2等）。既存API共通の
  X-API-KEY/Authorization: Bearer（require_public_api_key）で保護する
- フルのTAXIIページネーション（Content-Range・X-TAXII-Date-Added-* ヘッダー）。
  added_after・limit のみの簡易フィルタとする

**KEV向けの既存コレクションID・単一API root構成・エンドポイントパス・
レスポンス形式は一切変更していない**（既存クライアントの購読設定を壊さない
ための後方互換性維持）。
"""
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Security
from sqlalchemy.orm import Session

from app.core.auth import require_public_api_key
from app.core.database import get_db
from app.jvn.models import JvnVulnerability
from app.jvn.stix import build_stix_vulnerability as build_jvn_stix_vulnerability
from app.jvn.stix import stix_vulnerability_id as jvn_stix_vulnerability_id
from app.kev.models import Vulnerability
from app.kev.stix import build_stix_vulnerability as build_kev_stix_vulnerability
from app.kev.stix import stix_vulnerability_id as kev_stix_vulnerability_id
from app.osv.models import OsvVulnerability
from app.osv.stix import build_stix_vulnerability as build_osv_stix_vulnerability
from app.osv.stix import stix_vulnerability_id as osv_stix_vulnerability_id

logger = logging.getLogger(__name__)

_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
_STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

# 単一API root構成（KEV/OSV/JVNをまとめて同じapi-root配下のコレクションとして
# 配信する）。api-root名はKEV専用実装当時から変更しない
_API_ROOT = "cyberattack-info-api"


@dataclass(frozen=True)
class _CollectionSpec:
    """TAXIIコレクション1件の定義（クエリ・単体取得ロジックをドメインごとに差し替える）。"""

    collection_id: str
    title: str
    description: str
    # (db, added_after, limit) -> STIXオブジェクトのリスト
    query_objects: Callable[[Session, datetime | None, int], list[dict[str, Any]]]
    # (db, object_id) -> STIXオブジェクト（見つからなければNone）
    get_object: Callable[[Session, str], dict[str, Any] | None]


def _query_kev_objects(
    db: Session, added_after: datetime | None, limit: int,
) -> list[dict[str, Any]]:
    """KEVコレクションのobjects一覧を取得する（既存ロジックをそのまま移植）。"""
    query = db.query(Vulnerability)
    if added_after is not None:
        query = query.filter(Vulnerability.updated_at > added_after)
    items = query.order_by(Vulnerability.updated_at.asc()).limit(limit).all()
    return [build_kev_stix_vulnerability(v) for v in items]


def _get_kev_object(db: Session, object_id: str) -> dict[str, Any] | None:
    """KEVコレクションのobject単体取得（既存ロジックをそのまま移植）。

    STIXオブジェクトIDはCVE IDのuuid5ハッシュ（決定論的だが一方向）のため、
    逆引きにはCVE ID一覧との照合が必要。KEVカタログの規模（数千件程度）では
    線形走査でも実用上問題ない。
    """
    cve_ids = [row[0] for row in db.query(Vulnerability.cve_id).all()]
    matched = next((c for c in cve_ids if kev_stix_vulnerability_id(c) == object_id), None)
    if matched is None:
        return None
    item = db.query(Vulnerability).filter(Vulnerability.cve_id == matched).first()
    assert item is not None  # matchedはcve_ids一覧から取得したため必ず存在する
    return build_kev_stix_vulnerability(item)


def _query_osv_objects(
    db: Session, added_after: datetime | None, limit: int,
) -> list[dict[str, Any]]:
    """OSVコレクションのobjects一覧を取得する。"""
    query = db.query(OsvVulnerability)
    if added_after is not None:
        query = query.filter(OsvVulnerability.updated_at > added_after)
    items = query.order_by(OsvVulnerability.updated_at.asc()).limit(limit).all()
    return [build_osv_stix_vulnerability(v) for v in items]


def _get_osv_object(db: Session, object_id: str) -> dict[str, Any] | None:
    """OSVコレクションのobject単体取得。

    STIXオブジェクトIDは(osv_id, ecosystem, package_name)のuuid5ハッシュのため、
    逆引きには全組み合わせとの照合が必要（KEVと同じ線形走査方式）。
    """
    rows = db.query(
        OsvVulnerability.osv_id, OsvVulnerability.ecosystem, OsvVulnerability.package_name,
    ).all()
    matched = next(
        (row for row in rows if osv_stix_vulnerability_id(*row) == object_id), None,
    )
    if matched is None:
        return None
    osv_id, ecosystem, package_name = matched
    item = (
        db.query(OsvVulnerability)
        .filter(
            OsvVulnerability.osv_id == osv_id,
            OsvVulnerability.ecosystem == ecosystem,
            OsvVulnerability.package_name == package_name,
        )
        .first()
    )
    assert item is not None  # matchedはrows一覧から取得したため必ず存在する
    return build_osv_stix_vulnerability(item)


def _query_jvn_objects(
    db: Session, added_after: datetime | None, limit: int,
) -> list[dict[str, Any]]:
    """JVNコレクションのobjects一覧を取得する。"""
    query = db.query(JvnVulnerability)
    if added_after is not None:
        query = query.filter(JvnVulnerability.updated_at > added_after)
    items = query.order_by(JvnVulnerability.updated_at.asc()).limit(limit).all()
    return [build_jvn_stix_vulnerability(v) for v in items]


def _get_jvn_object(db: Session, object_id: str) -> dict[str, Any] | None:
    """JVNコレクションのobject単体取得（KEVと同じ線形走査方式）。"""
    jvndb_ids = [row[0] for row in db.query(JvnVulnerability.jvndb_id).all()]
    matched = next(
        (j for j in jvndb_ids if jvn_stix_vulnerability_id(j) == object_id), None,
    )
    if matched is None:
        return None
    item = db.query(JvnVulnerability).filter(JvnVulnerability.jvndb_id == matched).first()
    assert item is not None  # matchedはjvndb_ids一覧から取得したため必ず存在する
    return build_jvn_stix_vulnerability(item)


# コレクションレジストリ。KEVのcollection_idは変更禁止（既存クライアントの
# 購読設定が壊れるため）。OSV/JVNは今回新規追加する固定値
_COLLECTIONS: dict[str, _CollectionSpec] = {
    "d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a": _CollectionSpec(
        collection_id="d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a",
        title="CISA KEV Vulnerabilities",
        description="CISA KEV（悪用確認済み脆弱性）カタログのSTIX 2.1 Vulnerability SDO",
        query_objects=_query_kev_objects,
        get_object=_get_kev_object,
    ),
    "84be1117-7e69-58ed-a0dc-d2f2bb7f60ca": _CollectionSpec(
        collection_id="84be1117-7e69-58ed-a0dc-d2f2bb7f60ca",
        title="OSV Vulnerabilities",
        description="OSV（Open Source Vulnerabilities）のSTIX 2.1 Vulnerability SDO",
        query_objects=_query_osv_objects,
        get_object=_get_osv_object,
    ),
    "1c34f413-fd30-56cc-bf87-daf79113b5a8": _CollectionSpec(
        collection_id="1c34f413-fd30-56cc-bf87-daf79113b5a8",
        title="JVN Vulnerabilities",
        description="JVN（Japan Vulnerability Notes）のSTIX 2.1 Vulnerability SDO",
        query_objects=_query_jvn_objects,
        get_object=_get_jvn_object,
    ),
}


taxii_router = APIRouter(
    prefix="/taxii2",
    tags=["taxii"],
    dependencies=[Security(require_public_api_key)],
)


def _taxii_response(payload: dict[str, Any]) -> Response:
    return Response(content=json.dumps(payload), media_type=_TAXII_MEDIA_TYPE)


def _get_collection_or_404(collection_id: str) -> _CollectionSpec:
    spec = _COLLECTIONS.get(collection_id)
    if spec is None:
        raise HTTPException(status_code=404, detail="collection not found")
    return spec


def _validate_root(api_root: str) -> None:
    if api_root != _API_ROOT:
        raise HTTPException(status_code=404, detail="api-root not found")


def _validate_root_and_collection(api_root: str, collection_id: str) -> _CollectionSpec:
    _validate_root(api_root)
    return _get_collection_or_404(collection_id)


def _collection_resource(spec: _CollectionSpec) -> dict[str, Any]:
    return {
        "id": spec.collection_id,
        "title": spec.title,
        "description": spec.description,
        "can_read": True,
        "can_write": False,
        "media_types": [_STIX_MEDIA_TYPE],
    }


@taxii_router.get("/", summary="TAXII 2.1 Discovery")
def discovery() -> Response:
    """TAXIIサーバーのDiscoveryエンドポイント。利用可能なAPI rootを返す。"""
    return _taxii_response({
        "title": "サイバー攻撃情報API TAXII 2.1 サーバー",
        "description": (
            "CISA KEV（悪用確認済み脆弱性）・OSV（Open Source Vulnerabilities）・"
            "JVN（Japan Vulnerability Notes）をSTIX 2.1形式で配信する。"
        ),
        "default": f"/taxii2/{_API_ROOT}/",
        "api_roots": [f"/taxii2/{_API_ROOT}/"],
    })


@taxii_router.get("/{api_root}/", summary="TAXII 2.1 API Root")
def api_root_info(api_root: str) -> Response:
    """API rootの情報（対応バージョン・最大コンテンツ長）を返す。"""
    _validate_root(api_root)
    return _taxii_response({
        "title": "サイバー攻撃情報API",
        "description": "CISA KEV・OSV・JVNデータのTAXII 2.1配信",
        "versions": [_TAXII_MEDIA_TYPE],
        "max_content_length": 10_485_760,
    })


@taxii_router.get("/{api_root}/collections/", summary="TAXII 2.1 Collections")
def list_collections(api_root: str) -> Response:
    """このAPI root配下のコレクション一覧を返す（KEV/OSV/JVNの3件）。"""
    _validate_root(api_root)
    return _taxii_response({
        "collections": [_collection_resource(spec) for spec in _COLLECTIONS.values()],
    })


@taxii_router.get(
    "/{api_root}/collections/{collection_id}/", summary="TAXII 2.1 Collection",
)
def get_collection(api_root: str, collection_id: str) -> Response:
    """指定コレクションの情報を返す。"""
    spec = _validate_root_and_collection(api_root, collection_id)
    return _taxii_response(_collection_resource(spec))


@taxii_router.get(
    "/{api_root}/collections/{collection_id}/objects/", summary="TAXII 2.1 Objects",
)
def list_objects(
    api_root: str,
    collection_id: str,
    db: Annotated[Session, Depends(get_db)],
    added_after: datetime | None = Query(
        None, description="この日時以降に更新されたオブジェクトのみ返す（差分取得用）",
    ),
    limit: int = Query(100, ge=1, le=1000, description="最大取得件数"),
) -> Response:
    """コレクション内のSTIXオブジェクトを取得する。"""
    spec = _validate_root_and_collection(api_root, collection_id)

    objects = spec.query_objects(db, added_after, limit)

    logger.info(
        "taxii list_objects: collection=%s, added_after=%r, count=%d",
        collection_id, added_after, len(objects),
    )
    return _taxii_response({"objects": objects})


@taxii_router.get(
    "/{api_root}/collections/{collection_id}/objects/{object_id}/",
    summary="TAXII 2.1 Object（単体取得）",
)
def get_object(
    api_root: str, collection_id: str, object_id: str, db: Annotated[Session, Depends(get_db)],
) -> Response:
    """STIXオブジェクトIDを指定して1件取得する。

    STIXオブジェクトIDは各ドメインの自然キーのuuid5ハッシュ（決定論的だが
    一方向）のため、逆引きには自然キー一覧との照合が必要。各コレクションの
    規模（数千件程度）では線形走査でも実用上問題ない。
    """
    spec = _validate_root_and_collection(api_root, collection_id)

    stix_obj = spec.get_object(db, object_id)
    if stix_obj is None:
        raise HTTPException(status_code=404, detail="object not found")

    return _taxii_response({"objects": [stix_obj]})
