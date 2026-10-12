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
    パストラバーサル対策として `filter="data"`（PEP 706）で安全に展開する。
    """
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        try:
            tar.extractall(dest_dir, filter="data")
        except TypeError:
            # Python 3.11.4未満等、filter引数非対応の古いtarfileへのフォールバック
            # （本プロジェクトは3.11系を使うが、念のため後方互換を確保する）
            tar.extractall(dest_dir)  # noqa: S202

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
