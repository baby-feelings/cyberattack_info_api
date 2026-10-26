"""取得した tarball（リポジトリ全体）の安全な展開と、一時ディレクトリの管理。"""
import io
import os
import tarfile
import tempfile
from types import TracebackType


def extract_tarball(tarball_bytes: bytes, dest_dir: str) -> str:
    """tarball を安全に展開し、リポジトリソースのルートディレクトリパスを返す。

    GitHub の tarball エンドポイントは常に単一のトップレベルディレクトリ
    （例: `owner-repo-<sha>/`）を含むため、それを見つけてルートとして返す。
    パストラバーサル対策として `filter="data"`（PEP 706）で安全に展開する。本プロジェクトは
    Python 3.13 のみ（`filter` 引数が使える版）のため、フィルターなしで展開するフォールバックは
    持たない（古い版で動いてしまうより、動かずに気づける方が安全。Fail Fast）。
    """
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        tar.extractall(dest_dir, filter="data")

    entries = [
        e for e in os.listdir(dest_dir) if os.path.isdir(os.path.join(dest_dir, e))
    ]
    return os.path.join(dest_dir, entries[0]) if entries else dest_dir


class RepoArchive:
    """tarball を一時ディレクトリへ展開し、リポジトリのルートパスを渡す（`with` で使う）。

    一時ディレクトリは `with` を抜けるとき（例外時を含む）に必ず削除される。
    """

    def __init__(self, tarball_bytes: bytes) -> None:
        self._tarball_bytes = tarball_bytes
        self._tmp: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> str:
        self._tmp = tempfile.TemporaryDirectory()
        try:
            return extract_tarball(self._tarball_bytes, self._tmp.name)
        except BaseException:
            self._tmp.cleanup()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
