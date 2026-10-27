"""到達可能性解析のためのソースファイル収集（DEPSCAN）。

リポジトリ全体のファイルツリーから対象の拡張子のファイルを選び、内容を取得する。
GitHub への接続そのものは `app.core.github.repo.GitHubRepo` が担い、ここには DEPSCAN 固有の
判断（除外するディレクトリ・件数とサイズの上限）だけを置く。
"""
import logging

import httpx

from app.core.github.repo import GitHubRepo
from app.core.github.tree_paths import VENDORED_DIR_SEGMENTS, is_under_excluded_dir

logger = logging.getLogger(__name__)

# 到達可能性解析でソース走査から除外するディレクトリ（ベンダー化・生成物・依存物）
_EXCLUDED_DIR_SEGMENTS = VENDORED_DIR_SEGMENTS | {"deps", "_build", "packages"}

# 到達可能性解析で1リポジトリあたり取得するソースファイル数の上限
# （巨大リポジトリでの過剰な API 呼び出し・処理時間を防ぐための安全弁）
_MAX_SOURCE_FILES = 200
# 1ファイルあたりの取得上限サイズ（バイト。生成物・データファイル等の除外用）
_MAX_SOURCE_FILE_SIZE = 300_000


def collect_source_files(
    repo: GitHubRepo, default_branch: str, extensions: tuple[str, ...],
) -> dict[str, str]:
    """指定拡張子に一致するソースファイルの内容を取得する。

    ベンダー化・生成物ディレクトリ（node_modules 等）は除外し、1リポジトリあたりの
    ファイル数・サイズには安全弁として上限を設ける。

    Returns:
        {ファイルパス: 内容} の辞書（取得に失敗したファイル・大きすぎるファイルは含まれない）
    """
    matched_paths = [
        path for path in repo.tree(default_branch)
        if path.endswith(extensions)
        and not is_under_excluded_dir(path, _EXCLUDED_DIR_SEGMENTS)
    ][:_MAX_SOURCE_FILES]

    files: dict[str, str] = {}
    for path in matched_paths:
        try:
            content = repo.file_content(path)
        except httpx.HTTPError as exc:
            logger.warning("Failed to fetch source file %s in %s: %s", path, repo.full_name, exc)
            continue
        if len(content) <= _MAX_SOURCE_FILE_SIZE:
            files[path] = content
    return files
