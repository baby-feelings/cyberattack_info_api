"""依存ライブラリロックファイルパーサーのユニットテスト（DEPSCAN 機能）。"""
from app.dependency_parsers import PARSERS, DependencyRef, parse_manifest
from app.dependency_parsers.cargo_lock import parse_cargo_lock
from app.dependency_parsers.composer_lock import parse_composer_lock
from app.dependency_parsers.gemfile_lock import parse_gemfile_lock
from app.dependency_parsers.go_sum import parse_go_sum
from app.dependency_parsers.mix_lock import parse_mix_lock
from app.dependency_parsers.package_lock_json import parse_package_lock_json
from app.dependency_parsers.packages_lock_json import parse_packages_lock_json
from app.dependency_parsers.pom_xml import parse_pom_xml
from app.dependency_parsers.pubspec_lock import parse_pubspec_lock
from app.dependency_parsers.requirements_txt import parse_requirements_txt


class TestRequirementsTxt:
    def test_parses_pinned_versions(self):
        content = "fastapi==0.115.6\nrequests==2.31.0\n"
        refs = parse_requirements_txt(content)
        assert DependencyRef("PyPI", "fastapi", "0.115.6") in refs
        assert DependencyRef("PyPI", "requests", "2.31.0") in refs

    def test_ignores_range_specifiers(self):
        assert parse_requirements_txt("django>=4.2\n") == []

    def test_ignores_comments_and_blank_lines(self):
        content = "# comment\n\nfastapi==0.115.6\n"
        assert parse_requirements_txt(content) == [DependencyRef("PyPI", "fastapi", "0.115.6")]

    def test_strips_extras_and_markers(self):
        content = 'uvicorn[standard]==0.32.1 ; python_version >= "3.8"\n'
        assert parse_requirements_txt(content) == [DependencyRef("PyPI", "uvicorn", "0.32.1")]

    def test_ignores_editable_installs(self):
        assert parse_requirements_txt("-e .\n") == []


class TestPackageLockJson:
    def test_parses_lockfile_v2_packages(self):
        content = """
        {
          "lockfileVersion": 2,
          "packages": {
            "": {"name": "root"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/@scope/pkg": {"version": "1.0.0"}
          }
        }
        """
        refs = parse_package_lock_json(content)
        assert DependencyRef("npm", "express", "4.18.2") in refs
        assert DependencyRef("npm", "@scope/pkg", "1.0.0") in refs
        assert len(refs) == 2

    def test_invalid_json_returns_empty(self):
        assert parse_package_lock_json("not json") == []


class TestPubspecLock:
    def test_parses_packages(self):
        content = """
packages:
  dio:
    dependency: "direct main"
    version: "5.4.0"
  http:
    dependency: transitive
    version: "1.2.0"
"""
        refs = parse_pubspec_lock(content)
        assert DependencyRef("Pub", "dio", "5.4.0") in refs
        assert DependencyRef("Pub", "http", "1.2.0") in refs

    def test_invalid_yaml_returns_empty(self):
        assert parse_pubspec_lock("packages: [unclosed") == []


class TestGoSum:
    def test_dedupes_go_mod_lines(self):
        content = (
            "github.com/gin-gonic/gin v1.9.1 h1:abc=\n"
            "github.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n"
        )
        refs = parse_go_sum(content)
        assert refs == [DependencyRef("Go", "github.com/gin-gonic/gin", "v1.9.1")]


class TestPomXml:
    def test_parses_dependency_versions(self):
        content = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>${some.property}</version>
    </dependency>
  </dependencies>
</project>
"""
        refs = parse_pom_xml(content)
        assert refs == [DependencyRef("Maven", "org.springframework:spring-core", "5.3.20")]

    def test_invalid_xml_returns_empty(self):
        assert parse_pom_xml("<not-closed>") == []


class TestGemfileLock:
    def test_parses_top_level_specs_only(self):
        content = """GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      actionview (= 7.0.4)
    rails (7.0.4)

PLATFORMS
  ruby
"""
        refs = parse_gemfile_lock(content)
        assert DependencyRef("RubyGems", "actionpack", "7.0.4") in refs
        assert DependencyRef("RubyGems", "rails", "7.0.4") in refs
        assert len(refs) == 2


class TestPackagesLockJson:
    def test_parses_resolved_versions(self):
        content = """
        {
          "version": 1,
          "dependencies": {
            "net6.0": {
              "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}
            }
          }
        }
        """
        refs = parse_packages_lock_json(content)
        assert refs == [DependencyRef("NuGet", "Newtonsoft.Json", "13.0.1")]


class TestCargoLock:
    def test_parses_packages(self):
        content = """
[[package]]
name = "serde"
version = "1.0.130"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
        refs = parse_cargo_lock(content)
        assert refs == [DependencyRef("crates.io", "serde", "1.0.130")]

    def test_invalid_toml_returns_empty(self):
        assert parse_cargo_lock("not = [valid") == []


class TestComposerLock:
    def test_parses_packages_and_dev(self):
        content = """
        {
          "packages": [{"name": "laravel/framework", "version": "v10.0.0"}],
          "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]
        }
        """
        refs = parse_composer_lock(content)
        assert DependencyRef("Packagist", "laravel/framework", "10.0.0") in refs
        assert DependencyRef("Packagist", "phpunit/phpunit", "9.5.0") in refs


class TestMixLock:
    def test_parses_hex_entries(self):
        content = (
            '%{\n'
            '  "phoenix": {:hex, :phoenix, "1.7.10", "hash", [:mix], [], "hexpm", "hash"},\n'
            '  "ecto": {:hex, :ecto, "3.11.1", "hash", [:mix], [], "hexpm", "hash"},\n'
            '}\n'
        )
        refs = parse_mix_lock(content)
        assert DependencyRef("Hex", "phoenix", "1.7.10") in refs
        assert DependencyRef("Hex", "ecto", "3.11.1") in refs


class TestParseManifest:
    def test_dispatches_by_filename(self):
        refs = parse_manifest("requirements.txt", "fastapi==0.115.6\n")
        assert refs == [DependencyRef("PyPI", "fastapi", "0.115.6")]

    def test_unknown_filename_returns_empty(self):
        assert parse_manifest("unknown.txt", "content") == []

    def test_all_parsers_registered(self):
        # 10 エコシステム分のパーサーが揃っていることを確認
        assert len(PARSERS) == 10
