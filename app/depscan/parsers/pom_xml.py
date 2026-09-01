"""pom.xml（Maven）パーサー。

Maven はロックファイルを持たないため pom.xml を直接パースする。
`${property}` のような変数参照や親 POM 継承によるバージョン解決には対応しない
（スコープ外。直接バージョンが記載された依存のみ対象）。
"""
from defusedxml import ElementTree as ET

from app.depscan.parsers.base import DependencyRef


def parse_pom_xml(content: str) -> list[DependencyRef]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    # pom.xml は Maven の名前空間（http://maven.apache.org/POM/4.0.0）に属するため
    # ローカル名（タグ名末尾）で照合する
    def local_tag(elem: object) -> str:
        tag = getattr(elem, "tag", "")
        return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

    refs: list[DependencyRef] = []
    for dependency in root.iter():
        if local_tag(dependency) != "dependency":
            continue

        group_id = artifact_id = version = None
        for child in dependency:
            tag = local_tag(child)
            if tag == "groupId":
                group_id = (child.text or "").strip()
            elif tag == "artifactId":
                artifact_id = (child.text or "").strip()
            elif tag == "version":
                version = (child.text or "").strip()

        if not group_id or not artifact_id or not version:
            continue
        # 未解決の変数参照（${...}）はスキップ
        if version.startswith("${"):
            continue

        refs.append(DependencyRef("Maven", f"{group_id}:{artifact_id}", version))

    return refs
