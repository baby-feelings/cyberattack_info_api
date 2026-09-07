"""app.core.schemas.OrmDatetimeModel のテスト。

JVN/OSVスキーマ共通の基底クラス。ORMオブジェクトのdatetime属性を自動で
ISO文字列に変換する挙動と、新フィールド追加時の実装漏れを構造的に防ぐ
（フィールドを手動列挙しない）という設計意図を直接検証する。
"""
from datetime import datetime, timezone

from app.core.schemas import OrmDatetimeModel


class _Sample(OrmDatetimeModel):
    name: str
    created_at: str
    note: str | None = None


class _FakeOrmObject:
    """SQLAlchemy ORM インスタンスを模した、__dict__ を持つプレーンオブジェクト。"""

    def __init__(self, name: str, created_at: datetime, note: str | None = None):
        self.name = name
        self.created_at = created_at
        self.note = note


def test_converts_datetime_attribute_to_iso_string():
    obj = _FakeOrmObject(name="x", created_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    result = _Sample.model_validate(obj)
    assert result.created_at == "2026-01-01T00:00:00+00:00"


def test_leaves_non_datetime_attributes_untouched():
    obj = _FakeOrmObject(name="x", created_at=datetime(2026, 1, 1, tzinfo=timezone.utc), note="hi")
    result = _Sample.model_validate(obj)
    assert result.name == "x"
    assert result.note == "hi"


def test_new_field_not_enumerated_is_still_picked_up_automatically():
    """フィールドを手動列挙しないため、モデルに新フィールドを追加するだけで
    ORMオブジェクトの対応属性が自動的に拾われることを確認する
    （列挙し忘れによる本番バグ〈fetched_atがnullを返し続けた〉の再発防止）。
    """
    class _SampleWithExtraField(OrmDatetimeModel):
        name: str
        extra_field: str | None = None

    class _FakeWithExtra:
        def __init__(self):
            self.name = "x"
            self.extra_field = "should be picked up"

    result = _SampleWithExtraField.model_validate(_FakeWithExtra())
    assert result.extra_field == "should be picked up"


def test_missing_attribute_on_orm_object_falls_back_to_none():
    class _FakeMissingAttr:
        def __init__(self):
            self.name = "x"
            self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
            # note 属性を意図的に持たせない

    result = _Sample.model_validate(_FakeMissingAttr())
    assert result.note is None


def test_validates_plain_dict_via_standard_pydantic_path():
    """dict入力（__dict__を持たない）は通常のPydantic検証経路にそのまま委譲される。"""
    data = {"name": "x", "created_at": "2026-01-01T00:00:00+00:00", "note": None}
    result = _Sample.model_validate(data)
    assert result.name == "x"
    assert result.created_at == "2026-01-01T00:00:00+00:00"
