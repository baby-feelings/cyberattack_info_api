"""app.codescan.archive（tarball の安全な展開・一時ディレクトリの管理）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import io
import tarfile

import pytest

from app.codescan.archive import RepoArchive, extract_tarball  # noqa: E402
from tests.codescan.support import make_tarball  # noqa: E402


class TestExtractTarball:
    def test_extracts_and_returns_single_top_level_dir(self, tmp_path):
        tarball = make_tarball({"app/main.py": "print('hi')"}, top_dir="owner-repo-abc")
        dest = tmp_path / "extract"
        dest.mkdir()

        repo_root = extract_tarball(tarball, str(dest))

        assert os.path.basename(repo_root) == "owner-repo-abc"
        assert os.path.isfile(os.path.join(repo_root, "app", "main.py"))

    def test_returns_dest_dir_when_no_subdirectory(self, tmp_path):
        # トップレベルディレクトリを持たない（想定外だが安全に動作することを確認）tarball
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"content"
            info = tarfile.TarInfo(name="flat.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        dest = tmp_path / "extract2"
        dest.mkdir()

        repo_root = extract_tarball(buf.getvalue(), str(dest))

        assert repo_root == str(dest)


    def test_rejects_a_member_that_escapes_the_destination_directory(self, tmp_path):
        # 悪意あるリポジトリの tarball に含まれうる「../」で展開先の外へ書き出すメンバー
        # （パス名パラメータの未チェック／ディレクトリ・トラバーサル）。展開せずに拒否する
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"pwned"
            info = tarfile.TarInfo(name="owner-repo-abc/../../escaped.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        dest = tmp_path / "extract" / "inner"
        dest.mkdir(parents=True)

        with pytest.raises(tarfile.FilterError):
            extract_tarball(buf.getvalue(), str(dest))

        assert not (tmp_path / "escaped.txt").exists()
        assert not (tmp_path / "extract" / "escaped.txt").exists()


class TestRepoArchive:
    def test_yields_the_repo_root_with_extracted_files(self):
        tarball = make_tarball({"app/main.py": "print('hi')"}, top_dir="owner-repo-abc")
        with RepoArchive(tarball) as repo_root:
            assert os.path.basename(repo_root) == "owner-repo-abc"
            assert os.path.isfile(os.path.join(repo_root, "app", "main.py"))

    def test_removes_the_temporary_directory_on_exit(self):
        with RepoArchive(make_tarball({"a.txt": "x"})) as repo_root:
            pass
        assert not os.path.exists(repo_root)

    def test_removes_the_temporary_directory_when_the_body_raises(self):
        with pytest.raises(RuntimeError), RepoArchive(make_tarball({"a.txt": "x"})) as repo_root:
            seen = repo_root
            raise RuntimeError("boom")
        assert not os.path.exists(seen)

    def test_invalid_tarball_raises_and_leaves_no_directory(self):
        with pytest.raises(tarfile.TarError), RepoArchive(b"not a tarball"):
            pass
