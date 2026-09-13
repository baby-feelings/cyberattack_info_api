"""CISA KEVデータのTAXII 2.1配信（Issue #134）。

複数の脆弱性DB・APIを跨いで情報を収集する際、標準フォーマットの欠如が
相互運用の障害となっている問題に対応する。MISP等の既存CTI共有基盤や
SIEM/TIPからの購読を想定した、最小構成のTAXII 2.1サーバー実装
（discovery・api-root・collections・objects）を提供する。

対応範囲: 配信（読み取り専用）のみ。以下はスコープ外
（Issue #134本文もTAXIIを「将来的な拡張」と位置づけているため、
まずは購読可能な最小構成を提供する）:
- STIXオブジェクトのPUSH（書き込み）
- manifestエンドポイント（TAXII 2.1では任意〈MAY〉のため省略）
- TAXII固有の認証方式（OAuth2等）。既存API共通の
  X-API-KEY/Authorization: Bearer（require_public_api_key）で保護する
- フルのTAXIIページネーション（Content-Range・X-TAXII-Date-Added-* ヘッダー）。
  added_after・limit のみの簡易フィルタとする

配信データはKEV（CISA Known Exploited Vulnerabilities）のみ。OSV/JVNへの
拡張は必要になったタイミングで別途対応する。
"""
import json
import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Security
from sqlalchemy.orm import Session

from app.core.auth import require_public_api_key
from app.core.database import get_db
from app.kev.models import Vulnerability
from app.kev.stix import build_stix_vulnerability, stix_vulnerability_id

logger = logging.getLogger(__name__)

_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
_STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

# 単一API root・単一コレクション構成（KEVのみ配信するため複数持つ必要が無い）。
# コレクションIDは固定値（変更するとTAXIIクライアント側の購読設定が壊れるため
# 一度decideしたら変えない）
_API_ROOT = "cyberattack-info-api"
_COLLECTION_ID = "d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a"
_COLLECTION_TITLE = "CISA KEV Vulnerabilities"

taxii_router = APIRouter(
    prefix="/taxii2",
    tags=["taxii"],
    dependencies=[Security(require_public_api_key)],
)


def _taxii_response(payload: dict[str, Any]) -> Response:
    return Response(content=json.dumps(payload), media_type=_TAXII_MEDIA_TYPE)


def _validate_root_and_collection(api_root: str, collection_id: str) -> None:
    if api_root != _API_ROOT:
        raise HTTPException(status_code=404, detail="api-root not found")
    if collection_id != _COLLECTION_ID:
        raise HTTPException(status_code=404, detail="collection not found")


def _collection_resource() -> dict[str, Any]:
    return {
        "id": _COLLECTION_ID,
        "title": _COLLECTION_TITLE,
        "description": "CISA KEV（悪用確認済み脆弱性）カタログのSTIX 2.1 Vulnerability SDO",
        "can_read": True,
        "can_write": False,
        "media_types": [_STIX_MEDIA_TYPE],
    }


@taxii_router.get("/", summary="TAXII 2.1 Discovery")
def discovery() -> Response:
    """TAXIIサーバーのDiscoveryエンドポイント。利用可能なAPI rootを返す。"""
    return _taxii_response({
        "title": "サイバー攻撃情報API TAXII 2.1 サーバー",
        "description": "CISA KEV（悪用確認済み脆弱性）をSTIX 2.1形式で配信する。",
        "default": f"/taxii2/{_API_ROOT}/",
        "api_roots": [f"/taxii2/{_API_ROOT}/"],
    })


@taxii_router.get("/{api_root}/", summary="TAXII 2.1 API Root")
def api_root_info(api_root: str) -> Response:
    """API rootの情報（対応バージョン・最大コンテンツ長）を返す。"""
    if api_root != _API_ROOT:
        raise HTTPException(status_code=404, detail="api-root not found")
    return _taxii_response({
        "title": "サイバー攻撃情報API",
        "description": "CISA KEVデータのTAXII 2.1配信",
        "versions": [_TAXII_MEDIA_TYPE],
        "max_content_length": 10_485_760,
    })


@taxii_router.get("/{api_root}/collections/", summary="TAXII 2.1 Collections")
def list_collections(api_root: str) -> Response:
    """このAPI root配下のコレクション一覧を返す（現状KEV用の1件のみ）。"""
    if api_root != _API_ROOT:
        raise HTTPException(status_code=404, detail="api-root not found")
    return _taxii_response({"collections": [_collection_resource()]})


@taxii_router.get(
    "/{api_root}/collections/{collection_id}/", summary="TAXII 2.1 Collection",
)
def get_collection(api_root: str, collection_id: str) -> Response:
    """指定コレクションの情報を返す。"""
    _validate_root_and_collection(api_root, collection_id)
    return _taxii_response(_collection_resource())


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
    """コレクション内のSTIXオブジェクト（KEVレコード）を取得する。"""
    _validate_root_and_collection(api_root, collection_id)

    query = db.query(Vulnerability)
    if added_after is not None:
        query = query.filter(Vulnerability.updated_at > added_after)
    items = query.order_by(Vulnerability.updated_at.asc()).limit(limit).all()

    logger.info(
        "taxii list_objects: collection=%s, added_after=%r, count=%d",
        collection_id, added_after, len(items),
    )
    return _taxii_response({"objects": [build_stix_vulnerability(v) for v in items]})


@taxii_router.get(
    "/{api_root}/collections/{collection_id}/objects/{object_id}/",
    summary="TAXII 2.1 Object（単体取得）",
)
def get_object(
    api_root: str, collection_id: str, object_id: str, db: Annotated[Session, Depends(get_db)],
) -> Response:
    """STIXオブジェクトIDを指定して1件取得する。

    STIXオブジェクトIDはCVE IDのuuid5ハッシュ（決定論的だが一方向）のため、
    逆引きにはCVE ID一覧との照合が必要。KEVカタログの規模（数千件程度）では
    線形走査でも実用上問題ない。
    """
    _validate_root_and_collection(api_root, collection_id)

    cve_ids = [row[0] for row in db.query(Vulnerability.cve_id).all()]
    matched = next((c for c in cve_ids if stix_vulnerability_id(c) == object_id), None)
    if matched is None:
        raise HTTPException(status_code=404, detail="object not found")

    item = db.query(Vulnerability).filter(Vulnerability.cve_id == matched).first()
    assert item is not None  # matchedはcve_ids一覧から取得したため必ず存在する
    return _taxii_response({"objects": [build_stix_vulnerability(item)]})
