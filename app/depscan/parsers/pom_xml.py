"""pom.xml（Maven）パーサー。

Maven はロックファイルを持たないため pom.xml を直接パースする。
`${property}` のような変数参照や親 POM 継承によるバージョン解決には対応しない
（スコープ外。直接バージョンが記載された依存のみ対象）。
"""
from defusedxml import ElementTree as ET

from app.depscan.parsers.base import DependencyRef


def _local_tag(elem: object) -> str:
    """要素のタグ名から、名前空間（`{http://maven.apache.org/POM/4.0.0}`）を除いた部分。

    pom.xml は Maven の名前空間に属するため、ローカル名（タグ名の末尾）で照合する。
    """
    tag = getattr(elem, "tag", "")
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _dependency_ref(dependency: object) -> DependencyRef | None:
    """`<dependency>` 要素1つから、依存を取り出す。バージョンが直接書かれていなければ None。"""
    fields = {
        _local_tag(child): (getattr(child, "text", None) or "").strip()
        for child in dependency  # type: ignore[attr-defined]
    }
    group_id = fields.get("groupId")
    artifact_id = fields.get("artifactId")
    version = fields.get("version")
    if not group_id or not artifact_id or not version:
        return None
    # 未解決の変数参照（${...}）はスキップ
    if version.startswith("${"):
        return None
    return DependencyRef("Maven", f"{group_id}:{artifact_id}", version)


def parse_pom_xml(content: str) -> list[DependencyRef]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    refs = (_dependency_ref(e) for e in root.iter() if _local_tag(e) == "dependency")
    return [ref for ref in refs if ref is not None]
