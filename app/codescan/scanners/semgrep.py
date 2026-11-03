"""Semgrep（コードパターン診断）のスキャナー。
"""
import json
import logging
import os
import subprocess
from typing import Any

from app.codescan.cvss import calculate_base_score
from app.codescan.cvss_mapping import estimate_cvss_vector
from app.codescan.scanners.base import _MAX_SNIPPET_LEN, Scanner
from app.core.db_utils import now_utc

logger = logging.getLogger(__name__)


# 1リポジトリあたりのSemgrepサブプロセス全体のタイムアウト（秒）。OCI本番は
# 1 OCPU/6GBの限られたリソースのため、1リポジトリのスキャンが長時間ブロックすると
# 他のクローラー・CODESCAN全体を圧迫するリスクがある。超過時はそのリポジトリのみ
# スキップしログに記録し、CODESCAN全体は継続する
_SEMGREP_SUBPROCESS_TIMEOUT_SECONDS = 300
# Semgrep自体の内部タイムアウト（1ルール×1ファイルあたり、秒）
_SEMGREP_RULE_TIMEOUT_SECONDS = "120"


class SemgrepScanner(Scanner):
    """Semgrep（`p/security-audit` + `p/secrets`）によるコードパターン検知。"""

    name = "semgrep"

    def run(self, target_dir: str) -> dict[str, Any]:
        """Semgrep を実行し JSON 出力をパースして返す薄いラッパー。

        実際のバイナリ呼び出しをこの関数に閉じ込めることで、Semgrep 非依存の
        テスト（このラッパー自体をモックする）を可能にする。1リポジトリあたりの
        タイムアウトを必ず設定する（超過時は `subprocess.TimeoutExpired` を送出し、
        呼び出し元 `scan_repo` の try/except でそのリポジトリのみスキップされる）。
        """
        # S603/S607: semgrep は Dockerfile が /usr/local/bin に symlink する専用 venv の CLI を
        # PATH 経由で呼ぶ設計（引数は固定値と一時ディレクトリのみで、ユーザー入力を含まない）
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "semgrep",
                "--config=p/security-audit",
                "--config=p/secrets",
                "--json",
                "--timeout", _SEMGREP_RULE_TIMEOUT_SECONDS,
                "--quiet",
                target_dir,
            ],
            capture_output=True,
            timeout=_SEMGREP_SUBPROCESS_TIMEOUT_SECONDS,
            text=True,
            check=False,
        )
        return dict(json.loads(result.stdout or "{}"))

    def parse(
        self, full_name: str, raw: dict[str, Any], repo_root: str,
    ) -> list[dict[str, Any]]:
        """Semgrep の JSON 出力を `CodeFinding` 相当のレコード辞書リストへ変換する。

        CVSS 3.1 スコア・ベクターはこの時点で `app.codescan.cvss_mapping`
        （ベストエフォート推定）+ `app.codescan.cvss`（正式な計算式）により算出する。
        """
        now = now_utc()
        records: list[dict[str, Any]] = []

        for item in raw.get("results", []):
            raw_path = item.get("path", "")
            try:
                rel_path = os.path.relpath(raw_path, repo_root)
            except ValueError:
                # Windows でドライブレターが異なる等、relpath 不能な場合のフォールバック
                rel_path = raw_path
            rel_path = rel_path.replace("\\", "/")

            extra = item.get("extra", {})
            metadata = extra.get("metadata", {}) or {}

            cwe_raw = metadata.get("cwe") or []
            cwe_list = list(cwe_raw) if isinstance(cwe_raw, list) else [str(cwe_raw)]
            owasp_raw = metadata.get("owasp") or []
            owasp_list = list(owasp_raw) if isinstance(owasp_raw, list) else [str(owasp_raw)]

            severity = str(extra.get("severity") or "INFO").upper()
            snippet = str(extra.get("lines") or "")[:_MAX_SNIPPET_LEN]

            cvss_score: float | None = None
            cvss_vector: str | None = None
            try:
                cvss_vector = estimate_cvss_vector(severity, cwe_list)
                cvss_score = calculate_base_score(cvss_vector)
            except ValueError as exc:
                logger.warning(
                    "CODESCAN: failed to estimate CVSS for %s: %s", item.get("check_id"), exc,
                )

            records.append({
                "repo_full_name": full_name,
                "file_path": rel_path,
                "line_start": int(item.get("start", {}).get("line", 0)),
                "line_end": int(item.get("end", {}).get("line", 0)),
                "rule_id": str(item.get("check_id", "")),
                "message": str(extra.get("message") or "").strip(),
                "severity": severity,
                "cwe_ids": cwe_list,
                "owasp_categories": owasp_list,
                "code_snippet": snippet,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "tool": "semgrep",
                "detected_at": now,
            })

        return records
