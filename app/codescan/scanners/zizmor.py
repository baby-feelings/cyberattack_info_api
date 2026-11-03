"""zizmor（GitHub Actions のワークフロー設定の診断）のスキャナー。
"""
import json
import logging
import subprocess
from typing import Any

from app.codescan.scanners.base import _MAX_SNIPPET_LEN, Scanner
from app.core.db_utils import now_utc

logger = logging.getLogger(__name__)


# zizmor（GitHub Actions のワークフロー診断）の1リポジトリあたりのタイムアウト（秒）。
# オフライン実行でワークフローの YAML を読むだけのため、通常は数秒で終わる
_ZIZMOR_SUBPROCESS_TIMEOUT_SECONDS = 120
# ワークフローが1つも無い（または全て読めない）リポジトリで zizmor が stderr に出す文言。
# 多くのリポジトリが該当し、エラーではなく「検知なし」として扱う
_ZIZMOR_NO_INPUTS_MESSAGE = "no inputs collected"
# zizmor の severity（High/Medium/Low/Informational/Unknown）→ CODESCAN の重要度。
# 既存の Semgrep と同じ ERROR/WARNING/INFO にそろえる（Low 以下は INFO）
_ZIZMOR_SEVERITY = {"HIGH": "ERROR", "MEDIUM": "WARNING"}
# 代表的な指摘の対策（zizmor の指摘名 → 修正方法）。メッセージに添えて、何をすればよいかを示す
_ZIZMOR_FIX_HINTS = {
    "unpinned-uses": "アクションをタグ・ブランチでなく、コミットSHAで固定する",
    "excessive-permissions": "ワークフロー・ジョブの permissions を、必要な権限だけに絞る",
    "undocumented-permissions": "permissions の各権限に、必要な理由をコメントで書く",
    "dangerous-triggers": (
        "pull_request_target・workflow_run でPRのコードをチェックアウト・実行しない"
        "（pull_request に変える）"
    ),
    "template-injection": (
        "`${{ ... }}` を run に直接埋め込まず、環境変数（env）に渡して参照する"
    ),
    "self-hosted-runner": "セルフホストランナーで、信頼できないPRを動かさない",
    "artipacked": "actions/checkout に persist-credentials: false を指定する",
    "cache-poisoning": "リリース用のワークフローでは、キャッシュを使わない",
    "github-env": "GITHUB_ENV・GITHUB_PATH に、未信頼の入力を書き込まない",
}
# 検査レベル（persona）が auditor の指摘のうち、取り込むもの。zizmor は、誤検知を減らすため、
# 既定では regular（誤検知が少ない）の指摘だけを出す。セルフホストランナーは、使うこと自体が
# 問題とは限らないため auditor に分類されているが、信頼できないPRで動くと危険で、
# 使用を把握したいため（Issue #397）、これだけ取り込む。他の auditor・pedantic の指摘は、
# ノイズになるため除く
_ZIZMOR_AUDITOR_IDENTS_TO_KEEP = frozenset({"self-hosted-runner"})
# スニペットを保存しない指摘。認証情報そのものが書かれている可能性があるため
# （gitleaks と同じく、シークレットの実際の値を DB に保存しない）
_ZIZMOR_NO_SNIPPET_IDENTS = frozenset({"hardcoded-container-credentials"})


class ZizmorScanner(Scanner):
    """zizmor による GitHub Actions ワークフローの診断（Issue #397）。

    CI は供給網の一部で、ワークフローの不備はシークレットの窃取や改ざんにつながる
    （2025年の `tj-actions/changed-files` の事例）。未固定のアクション・過剰な権限・
    コマンド注入（template-injection）・危険なトリガー（`pull_request_target` 等）を検知する。
    ネットワークには接続しない（`--offline`）ため、GitHub のトークンを渡さず、API の
    レート制限も受けない。オンライン診断（既知の脆弱なアクション・偽造コミットの参照）は含まない。
    """

    name = "zizmor"

    def run(self, target_dir: str) -> list[dict[str, Any]]:
        """zizmor を実行し、JSON 出力（指摘のリスト）を返す薄いラッパー。

        `target_dir` を作業ディレクトリにして `.` を対象にし、パスをリポジトリ基準の相対にする。
        ワークフローが無いリポジトリは、終了コード 3・標準出力なしで終わる（エラーではない）。
        それ以外で出力が無いのはツールの失敗のため、`OSError` で伝える（検知 0 件として扱うと、
        既存の検知を「解決済み」にしてしまうため）。
        """
        # S603/S607: zizmor は Dockerfile が /usr/local/bin に symlink する専用 venv の CLI を
        # PATH 経由で呼ぶ設計（引数は固定値のみで、ユーザー入力を含まない）
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "zizmor", "--offline", "--persona", "auditor",
                "--format", "json", "--no-exit-codes", "--quiet", ".",
            ],
            cwd=target_dir,
            capture_output=True,
            timeout=_ZIZMOR_SUBPROCESS_TIMEOUT_SECONDS,
            # ワークフローに日本語のコメント等があっても、環境の既定の文字コードに左右されない
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.stdout.strip():
            parsed = json.loads(result.stdout)
            return list(parsed) if isinstance(parsed, list) else []
        if _ZIZMOR_NO_INPUTS_MESSAGE in result.stderr:
            return []
        raise OSError(f"zizmor failed (exit {result.returncode}): {result.stderr.strip()[:300]}")

    @staticmethod
    def _primary_location(item: dict[str, Any]) -> dict[str, Any] | None:
        """指摘の主たる場所（`Primary`。無ければ先頭）。"""
        locations = item.get("locations") or []
        for location in locations:
            if (location.get("symbolic") or {}).get("kind") == "Primary":
                return dict(location)
        return dict(locations[0]) if locations else None

    @staticmethod
    def _relative_path(location: dict[str, Any], repo_root: str) -> str | None:
        """ワークフローの、リポジトリ基準の相対パス（`/` 区切り）。ローカル以外は None。"""
        local = ((location.get("symbolic") or {}).get("key") or {}).get("Local")
        if not local:
            return None
        # OS によらず同じ結果になるよう、区切りを `/` にそろえた文字列として扱う
        path = str(local.get("verbatim_path") or "").replace("\\", "/")
        root = repo_root.replace("\\", "/").rstrip("/")
        if root and path.startswith(f"{root}/"):
            path = path[len(root) + 1:]
        while path.startswith("./"):
            path = path[2:]
        return path

    def parse(
        self, full_name: str, raw: list[dict[str, Any]], repo_root: str,
    ) -> list[dict[str, Any]]:
        """zizmor の JSON 出力を `CodeFinding` 相当のレコード辞書リストへ変換する。

        - `# zizmor: ignore[...]` で除外された指摘（`ignored`）は含めない
        - 検査レベルが regular の指摘と、取り込む auditor の指摘（セルフホストランナー）だけにする
        - 行番号は zizmor が 0 始まりのため、1 を足す
        - CVSS は推定しない（脆弱性そのものではなく、設定の不備のため）
        """
        now = now_utc()
        records: list[dict[str, Any]] = []

        for item in raw:
            if item.get("ignored"):
                continue
            ident = str(item.get("ident") or "unknown")
            persona = str((item.get("determinations") or {}).get("persona") or "").upper()
            if persona != "REGULAR" and ident not in _ZIZMOR_AUDITOR_IDENTS_TO_KEEP:
                continue
            location = self._primary_location(item)
            rel_path = self._relative_path(location, repo_root) if location else None
            if location is None or not rel_path:
                continue

            symbolic = location.get("symbolic") or {}
            concrete = location.get("concrete") or {}
            span = concrete.get("location") or {}
            line_start = int((span.get("start_point") or {}).get("row", 0)) + 1
            line_end = int((span.get("end_point") or {}).get("row", line_start - 1)) + 1

            severity_text = str((item.get("determinations") or {}).get("severity") or "")
            message = str(item.get("desc") or ident)
            if symbolic.get("annotation"):
                message += f"（{symbolic['annotation']}）"
            if ident in _ZIZMOR_FIX_HINTS:
                message += f" 対策: {_ZIZMOR_FIX_HINTS[ident]}。"
            if item.get("url"):
                message += f" 詳細: {item['url']}"

            snippet = ""
            if ident not in _ZIZMOR_NO_SNIPPET_IDENTS:
                snippet = str(concrete.get("feature") or "")[:_MAX_SNIPPET_LEN]

            records.append({
                "repo_full_name": full_name,
                "file_path": rel_path,
                "line_start": line_start,
                "line_end": line_end,
                # Semgrep・gitleaks の rule_id との衝突を避けるため、ツール名の接頭辞を付ける
                "rule_id": f"zizmor:{ident}",
                "message": message,
                "severity": _ZIZMOR_SEVERITY.get(severity_text.upper(), "INFO"),
                "cwe_ids": [],
                "owasp_categories": [],
                "code_snippet": snippet,
                "cvss_score": None,
                "cvss_vector": None,
                "tool": "zizmor",
                "detected_at": now,
            })

        return records
