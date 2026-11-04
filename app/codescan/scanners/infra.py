"""インフラ設定（Firebase のルール・Dockerfile・compose）の診断のスキャナー。
"""
import logging
import os
from typing import Any

from app.codescan import iac_rules
from app.codescan.scanners.base import _MAX_SNIPPET_LEN, Scanner
from app.core.db_utils import now_utc

logger = logging.getLogger(__name__)


# インフラ設定の診断（InfraScanner）で読む、ファイルの種類ごとの判定
# （ファイル名の判定 → ルール関数）。Terraform・Kubernetes は、現時点では対象外
_IAC_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__",
    ".dart_tool", ".next", "target", ".gradle", "Pods",
})
# 1ファイルの読み取り上限（バイト）と、1リポジトリで読むファイル数の上限
# （巨大・大量の生成物への備え）
_IAC_MAX_FILE_BYTES = 200_000
# `dockerfile.py` のように、Dockerfile と名前が似たソースコード・文書は、
# 設定ファイルではないため対象にしない
# （Dockerfile の接尾辞は `Dockerfile.dev` のような環境名で、これらの拡張子にはならない）
_NOT_CONFIG_SUFFIXES = (
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt",
    ".rb", ".php", ".cs", ".sh", ".md", ".txt", ".rst", ".json", ".html", ".css", ".snap",
)
_IAC_MAX_FILES = 200


def _iac_rules_for(filename: str):
    """ファイル名から、適用する診断ルールを選ぶ（対象外のファイルは None）。"""
    lowered = filename.lower()
    if lowered in ("firestore.rules", "storage.rules"):
        return iac_rules.check_firebase_rules
    if lowered == "database.rules.json":
        return iac_rules.check_realtime_db_rules
    if lowered == "firebase.json":
        return iac_rules.check_firebase_json
    is_dockerfile_name = (
        lowered == "dockerfile"
        or lowered.startswith("dockerfile.")
        or lowered.endswith(".dockerfile")
    )
    if is_dockerfile_name and not lowered.endswith(_NOT_CONFIG_SUFFIXES):
        return iac_rules.check_dockerfile
    if lowered.endswith((".yml", ".yaml")) and (
        lowered.startswith(("docker-compose", "compose"))
    ):
        return iac_rules.check_docker_compose
    return None


class InfraScanner(Scanner):
    """インフラ設定（Firebase のルール・`firebase.json`・Dockerfile・compose）の診断（Issue #400）。

    Firestore・Storage のルールの過剰な公開（`allow read, write: if true`）は、
    データ漏えいに直結する。外部ツールは使わず、`iac_rules` の判定で、ファイルを読んで検査する
    （ネットワーク・サブプロセスなし）。
    シークレットの値は、検知結果に残さない（キー名だけを示す）。
    """

    name = "iac"

    def run(self, target_dir: str) -> list[tuple[str, str]]:
        """対象のファイルを探して、(リポジトリ基準の相対パス, 内容) の一覧を返す。"""
        found: list[tuple[str, str]] = []
        for dirpath, dirnames, filenames in os.walk(target_dir):
            # 依存・生成物・履歴のディレクトリには入らない（順序を固定し、結果を安定させる）
            dirnames[:] = sorted(d for d in dirnames if d not in _IAC_SKIP_DIRS)
            for filename in sorted(filenames):
                if _iac_rules_for(filename) is None:
                    continue
                path = os.path.join(dirpath, filename)
                try:
                    if os.path.getsize(path) > _IAC_MAX_FILE_BYTES:
                        continue
                    with open(path, encoding="utf-8", errors="replace") as handle:
                        text = handle.read()
                except OSError:
                    continue
                relative = os.path.relpath(path, target_dir).replace(os.sep, "/")
                found.append((relative, text))
                if len(found) >= _IAC_MAX_FILES:
                    return found
        return found

    def parse(
        self, full_name: str, raw: list[tuple[str, str]], repo_root: str,
    ) -> list[dict[str, Any]]:
        """ファイルの内容に診断ルールを当て、`CodeFinding` 相当のレコード辞書リストへ変換する。

        CVSS は推定しない（脆弱性そのものではなく、設定の不備のため。zizmor と同じ）。
        """
        now = now_utc()
        records: list[dict[str, Any]] = []
        for relative, text in raw:
            check = _iac_rules_for(os.path.basename(relative))
            if check is None:
                continue
            for issue in check(text):
                records.append({
                    "repo_full_name": full_name,
                    "file_path": relative,
                    "line_start": issue.line,
                    "line_end": issue.line,
                    # 他ツールの rule_id との衝突を避けるため、ツール名の接頭辞を付ける
                    "rule_id": f"iac:{issue.rule}",
                    "message": issue.message,
                    "severity": issue.severity,
                    "cwe_ids": [issue.cwe] if issue.cwe else [],
                    "owasp_categories": [],
                    "code_snippet": issue.snippet[:_MAX_SNIPPET_LEN],
                    "cvss_score": None,
                    "cvss_vector": None,
                    "tool": "iac",
                    "detected_at": now,
                })
        return records
