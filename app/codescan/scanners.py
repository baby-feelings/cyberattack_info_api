"""コード脆弱性の検査ツール（Semgrep・gitleaks・zizmor）。ツールごとに `Scanner`（Strategy）を実装。

各スキャナーは、ツールの実行（`run`）と、出力のレコード化（`parse`。`CodeFinding` 相当）を持つ。
実際のバイナリ呼び出しを `run` に閉じ込めることで、ツールが無い開発環境（Windows 等）でも
`run` をモックしてテストできる。ツールを足すときは `Scanner` を継承し、`default_scanners` に加える。

【重要・セキュリティ】gitleaks の JSON 出力には検知したシークレットの実際の値（`Secret`）が
平文で含まれる。これを DB に保存したり API レスポンスとして返したりすると、自アプリの脆弱性診断が
実際の認証情報を漏洩させるという本末転倒な事故になる。そのため `GitleaksScanner.parse` は `Secret`
フィールドを一切参照せず、`code_snippet` には `Description`（ルールの説明。例:「AWS Access Key」）
のみを固定文言「検知内容: {Description}」として格納する（詳細は codescan スキル）。
"""
import contextlib
import json
import logging
import os
import subprocess
import tempfile
from abc import ABC, abstractmethod
from typing import Any

from app.codescan.cvss import calculate_base_score
from app.codescan.cvss_mapping import estimate_cvss_vector
from app.crawler_logs.writer import now_utc

logger = logging.getLogger(__name__)

# 1リポジトリあたりのSemgrepサブプロセス全体のタイムアウト（秒）。OCI本番は
# 1 OCPU/6GBの限られたリソースのため、1リポジトリのスキャンが長時間ブロックすると
# 他のクローラー・CODESCAN全体を圧迫するリスクがある。超過時はそのリポジトリのみ
# スキップしログに記録し、CODESCAN全体は継続する
_SEMGREP_SUBPROCESS_TIMEOUT_SECONDS = 300
# Semgrep自体の内部タイムアウト（1ルール×1ファイルあたり、秒）
_SEMGREP_RULE_TIMEOUT_SECONDS = "120"
# コードスニペットの保存上限文字数（生成物混入等の異常ケースでDBが肥大化しないため）
_MAX_SNIPPET_LEN = 2000

# 1リポジトリあたりのgitleaksサブプロセス全体のタイムアウト（秒）。gitleaksは
# 正規表現ベースのシークレット検知で一般にSemgrepより高速だが、大きなリポジトリも
# 考慮し余裕を持たせる（Semgrepの300秒より短めでよい）
_GITLEAKS_SUBPROCESS_TIMEOUT_SECONDS = 120


class Scanner(ABC):
    """コード検査ツールの共通の形（Strategy）。`scan` が実行→変換の流れ（Template Method）。

    実行（`run`）の失敗（タイムアウト・出力の解析失敗）は例外として伝わる。呼び出し側
    （`crawler.scan_repo`）がスキャナーごとに独立して捕捉し、一方が失敗しても他方の結果を活かす。
    """

    #: ログ・識別用のツール名（`CodeFinding.tool` と同じ値）
    name: str

    @abstractmethod
    def run(self, target_dir: str) -> Any:
        """ツールを実行し、出力（パース済みの JSON）を返す。"""

    @abstractmethod
    def parse(self, full_name: str, raw: Any, repo_root: str) -> list[dict[str, Any]]:
        """`run` の出力を、`CodeFinding` 相当のレコード辞書リストへ変換する。"""

    def scan(self, full_name: str, repo_root: str) -> list[dict[str, Any]]:
        """1リポジトリ（展開済みのルート）を検査して、レコードを返す。"""
        return self.parse(full_name, self.run(repo_root), repo_root)


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


def default_scanners() -> tuple[Scanner, ...]:
    """CODESCAN が使うスキャナー（Semgrep・gitleaks・zizmor。互いに独立して実行される）。"""
    return (SemgrepScanner(), GitleaksScanner(), ZizmorScanner())
