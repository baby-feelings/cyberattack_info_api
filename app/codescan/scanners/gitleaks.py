"""gitleaks（ハードコードされたシークレットの検知）のスキャナー。

【重要・セキュリティ】gitleaks の JSON 出力には、検知したシークレットの実際の値（`Secret`）が
平文で含まれる。`parse` は `Secret` を一切参照せず、`code_snippet` には `Description` のみを
固定文言で格納する（詳細は codescan スキル）。
"""
import contextlib
import json
import logging
import os
import subprocess
import tempfile
from typing import Any

from app.codescan.cvss import calculate_base_score
from app.codescan.cvss_mapping import estimate_cvss_vector
from app.codescan.scanners.base import _MAX_SNIPPET_LEN, Scanner
from app.core.db_utils import now_utc

logger = logging.getLogger(__name__)


# 1リポジトリあたりのgitleaksサブプロセス全体のタイムアウト（秒）。gitleaksは
# 正規表現ベースのシークレット検知で一般にSemgrepより高速だが、大きなリポジトリも
# 考慮し余裕を持たせる（Semgrepの300秒より短めでよい）
_GITLEAKS_SUBPROCESS_TIMEOUT_SECONDS = 120


class GitleaksScanner(Scanner):
    """gitleaks によるシークレット（ハードコードされた認証情報）検知（Issue #219）。"""

    name = "gitleaks"

    def run(self, target_dir: str) -> list[dict[str, Any]]:
        """gitleaks を実行し JSON レポートをパースして返す薄いラッパー。

        Semgrep と同じ方針で、実際のバイナリ呼び出しをこの関数に閉じ込めることで
        Windows 開発環境（gitleaks バイナリが無い）でもこのラッパー自体をモックして
        テストできるようにする。`--no-git`（tarball 展開のため Git 履歴が無い）・
        `--exit-code 0`（シークレット検知時の非ゼロ終了を防ぎ、Semgrep と同様に
        「検知があっても正常終了として扱い JSON 出力をパースする」設計に統一する）
        が必須。1リポジトリあたりのタイムアウトを必ず設定する（超過時は
        `subprocess.TimeoutExpired` を送出し、呼び出し元 `scan_repo` の try/except
        により gitleaks の結果のみスキップされ、Semgrep の結果は活かされる）。

        対象リポジトリのルートに `.gitleaks.toml` が存在すれば `--config` で
        明示的に渡す（gitleaksはデフォルトでは`--source`配下の設定ファイルを
        自動探索しないため）。これにより各リポジトリが自身のallowlist
        （テストフィクスチャのダミーシークレット等の既知の誤検知除外）を
        持てるようにする（Issue #221: 本リポジトリ自身のテストコード内の
        ダミーAWSキーが検知され続けていた問題への対応）。
        """
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False,
        ) as report_file:
            report_path = report_file.name

        cmd = [
            "gitleaks",
            "detect",
            "--source", target_dir,
            "--no-git",
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",
        ]
        repo_config_path = os.path.join(target_dir, ".gitleaks.toml")
        if os.path.isfile(repo_config_path):
            cmd.extend(["--config", repo_config_path])

        try:
            subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                timeout=_GITLEAKS_SUBPROCESS_TIMEOUT_SECONDS,
                text=True,
                check=False,
            )
            with open(report_path, encoding="utf-8") as f:
                content = f.read().strip()
            # 検知0件の場合 gitleaks は `[]` を書くが、念のため空文字列もフォールバックする
            parsed = json.loads(content) if content else []
            return list(parsed) if isinstance(parsed, list) else []
        finally:
            with contextlib.suppress(OSError):
                os.remove(report_path)

    def parse(
        self, full_name: str, raw: list[dict[str, Any]], repo_root: str,
    ) -> list[dict[str, Any]]:
        """gitleaks の JSON 出力を `CodeFinding` 相当のレコード辞書リストへ変換する。

        【重要・セキュリティ】gitleaks の各エントリには検知したシークレットの実際の
        値（`Secret` フィールド）が平文で含まれるが、このフィールドは一切参照しない。
        `code_snippet` には `Description`（ルールの説明）のみを固定文言として格納し、
        シークレット値そのものを DB へ保存しない（モジュール docstring 参照）。

        gitleaks のハードコード認証情報検知は CWE-798 に相当するため、CVSS ベクター
        推定は既存の `app.codescan.cvss_mapping` の CWE-798 マッピングをそのまま
        再利用する（severity の概念が gitleaks には無いため、常に "ERROR" 相当として
        扱う）。
        """
        now = now_utc()
        records: list[dict[str, Any]] = []

        for item in raw:
            # gitleaksの`File`フィールドは`--source`ディレクトリを基準にした相対パスの
            # 場合と絶対パスの場合があり、バージョン・実行環境によって挙動が揺れる。
            # Semgrepの_parse_semgrep_resultsと同じくos.path.relpathで確実に
            # repo_root基準の相対パスへ正規化する（元が既に相対パスであっても
            # os.path.relpathは冪等に動作するため問題ない）。これを怠ると
            # tempfile.TemporaryDirectory()が生成するランダムなディレクトリ名が
            # file_pathに残り、Upsertの自然キーが毎回変わって重複が際限なく
            # 蓄積するバグになる（本番の初回実行で実際に発生し発覚した）。
            raw_path = str(item.get("File", ""))
            try:
                rel_path = (
                    os.path.relpath(raw_path, repo_root) if os.path.isabs(raw_path) else raw_path
                )
            except ValueError:
                rel_path = raw_path
            rel_path = rel_path.replace("\\", "/")
            line_start = int(item.get("StartLine") or 0)
            line_end = int(item.get("EndLine") or line_start)
            # Semgrepのrule_id（"python.lang.security...."）との衝突を避けるため
            # gitleaks由来には明示的にプレフィックスを付与する
            rule_id = f"gitleaks:{item.get('RuleID', 'unknown')}"
            description = str(item.get("Description") or "Secret detected")

            cvss_score: float | None = None
            cvss_vector: str | None = None
            try:
                cvss_vector = estimate_cvss_vector("ERROR", ["CWE-798"])
                cvss_score = calculate_base_score(cvss_vector)
            except ValueError as exc:
                logger.warning(
                    "CODESCAN: failed to estimate CVSS for gitleaks finding %s: %s",
                    rule_id, exc,
                )

            records.append({
                "repo_full_name": full_name,
                "file_path": rel_path,
                "line_start": line_start,
                "line_end": line_end,
                "rule_id": rule_id,
                "message": description,
                "severity": "ERROR",
                "cwe_ids": ["CWE-798"],
                "owasp_categories": [],
                # シークレットの実際の値（Secret）は絶対に保存しない
                "code_snippet": f"検知内容: {description}"[:_MAX_SNIPPET_LEN],
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "tool": "gitleaks",
                "detected_at": now,
            })

        return records
