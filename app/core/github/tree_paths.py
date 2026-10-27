"""リポジトリのファイルツリーのパスに対する、共通の判定（GitHub から読むファイルの絞り込み）。

DEPSCAN（到達可能性解析のソース収集）と RUNTIME（言語・実行環境の設定ファイルの検出）が、
それぞれ「依存物・生成物のディレクトリ配下を読まない」判定を持っていた。共通の部分
（`VENDORED_DIR_SEGMENTS`）と判定の関数をここに置き、用途ごとの違いだけを呼び出し側で足す。
"""

# どの用途でも読まないディレクトリ（依存物・生成物・仮想環境・バージョン管理）
VENDORED_DIR_SEGMENTS: frozenset[str] = frozenset({
    "node_modules", "vendor", ".git", "dist", "build", "venv", ".venv", "__pycache__", "target",
})


def is_under_excluded_dir(path: str, excluded: frozenset[str]) -> bool:
    """パスのディレクトリ部分（ファイル名を除く）に、除外するディレクトリ名があるか。"""
    return any(segment in excluded for segment in path.split("/")[:-1])
