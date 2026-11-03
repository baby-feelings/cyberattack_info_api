"""コード脆弱性の検査ツール（Semgrep・gitleaks・zizmor・インフラ設定）。

ツールごとに `Scanner`（Strategy）を実装する。

各スキャナーは、ツールの実行（`run`）と、出力のレコード化（`parse`。`CodeFinding` 相当）を持つ。
実際のバイナリ呼び出しを `run` に閉じ込めることで、ツールが無い開発環境（Windows 等）でも
`run` をモックしてテストできる。ツールを足すときは `Scanner` を継承し、`default_scanners` に加える。

【重要・セキュリティ】gitleaks の JSON 出力には検知したシークレットの実際の値（`Secret`）が
平文で含まれる。これを DB に保存したり API レスポンスとして返したりすると、自アプリの脆弱性診断が
実際の認証情報を漏洩させるという本末転倒な事故になる。そのため `GitleaksScanner.parse` は `Secret`
フィールドを一切参照せず、`code_snippet` には `Description`（ルールの説明。例:「AWS Access Key」）
のみを固定文言「検知内容: {Description}」として格納する（詳細は codescan スキル）。
"""
from app.codescan.scanners.base import Scanner
from app.codescan.scanners.gitleaks import GitleaksScanner
from app.codescan.scanners.infra import InfraScanner
from app.codescan.scanners.semgrep import SemgrepScanner
from app.codescan.scanners.zizmor import ZizmorScanner

__all__ = [
    "GitleaksScanner", "InfraScanner", "Scanner", "SemgrepScanner", "ZizmorScanner",
    "default_scanners",
]


def default_scanners() -> tuple[Scanner, ...]:
    """CODESCAN が使うスキャナー（Semgrep・gitleaks・zizmor・インフラ。互いに独立して実行）。"""
    return (SemgrepScanner(), GitleaksScanner(), ZizmorScanner(), InfraScanner())
