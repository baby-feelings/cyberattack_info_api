"""app.core.github.tree_paths（ファイルツリーのパスの除外判定）のテスト。"""
from app.core.github.tree_paths import VENDORED_DIR_SEGMENTS, is_under_excluded_dir


class TestIsUnderExcludedDir:
    def test_excludes_files_under_a_vendored_directory(self):
        assert is_under_excluded_dir("node_modules/x/package.json", VENDORED_DIR_SEGMENTS)
        assert is_under_excluded_dir("app/venv/lib/site.py", VENDORED_DIR_SEGMENTS)

    def test_keeps_ordinary_paths(self):
        assert not is_under_excluded_dir("src/main.py", VENDORED_DIR_SEGMENTS)
        assert not is_under_excluded_dir("Dockerfile", VENDORED_DIR_SEGMENTS)

    def test_only_directories_count_not_the_file_name(self):
        """ファイル名が除外名と同じでも、ディレクトリではないため除外しない。"""
        assert not is_under_excluded_dir("docs/vendor", VENDORED_DIR_SEGMENTS)

    def test_extra_directories_can_be_added_per_use(self):
        extra = VENDORED_DIR_SEGMENTS | {"packages"}
        assert is_under_excluded_dir("packages/a/pkg.json", extra)
        assert not is_under_excluded_dir("packages/a/pkg.json", VENDORED_DIR_SEGMENTS)
