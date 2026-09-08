"""app.depscan.reachability（DEPSCAN 到達可能性ヒューリスティック）のテスト。

10エコシステムそれぞれについて、import/use文からreachable判定できること、
該当パッケージが見つからない場合はunreachable、ソースが無い場合はunknownに
なることを検証する。
"""
from app.depscan.reachability import check_reachability


class TestCheckReachabilityCommon:
    def test_empty_source_files_is_unknown(self):
        assert check_reachability("PyPI", "requests", {}) == "unknown"

    def test_no_match_is_unreachable(self):
        source = {"app/main.py": "import os\nimport sys\n"}
        assert check_reachability("PyPI", "requests", source) == "unreachable"


class TestPyPI:
    def test_plain_import_is_reachable(self):
        source = {"app/main.py": "import requests\n"}
        assert check_reachability("PyPI", "requests", source) == "reachable"

    def test_from_import_is_reachable(self):
        source = {"app/main.py": "from requests import Session\n"}
        assert check_reachability("PyPI", "requests", source) == "reachable"

    def test_does_not_match_prefix_of_other_package(self):
        """"requests" は "requests_toolbelt" の import にマッチしないこと。"""
        source = {"app/main.py": "import requests_toolbelt\n"}
        assert check_reachability("PyPI", "requests", source) == "unreachable"

    def test_override_map_handles_pyyaml(self):
        source = {"app/main.py": "import yaml\n"}
        assert check_reachability("PyPI", "PyYAML", source) == "reachable"

    def test_override_map_handles_beautifulsoup4(self):
        source = {"app/main.py": "from bs4 import BeautifulSoup\n"}
        assert check_reachability("PyPI", "beautifulsoup4", source) == "reachable"

    def test_hyphen_normalized_to_underscore(self):
        source = {"app/main.py": "import python_dotenv_like_pkg\n"}
        assert check_reachability("PyPI", "python-dotenv-like-pkg", source) == "reachable"


class TestNpm:
    def test_require_is_reachable(self):
        source = {"src/index.js": "const express = require('express')\n"}
        assert check_reachability("npm", "express", source) == "reachable"

    def test_es_import_is_reachable(self):
        source = {"src/index.ts": "import express from 'express'\n"}
        assert check_reachability("npm", "express", source) == "reachable"

    def test_subpath_import_is_reachable(self):
        source = {"src/index.ts": "import { debounce } from 'lodash/debounce'\n"}
        assert check_reachability("npm", "lodash", source) == "reachable"

    def test_unrelated_package_is_unreachable(self):
        source = {"src/index.ts": "import express from 'express'\n"}
        assert check_reachability("npm", "koa", source) == "unreachable"


class TestPub:
    def test_package_import_is_reachable(self):
        source = {"lib/main.dart": "import 'package:http/http.dart' as http;\n"}
        assert check_reachability("Pub", "http", source) == "reachable"

    def test_unrelated_package_is_unreachable(self):
        source = {"lib/main.dart": "import 'package:http/http.dart' as http;\n"}
        assert check_reachability("Pub", "dio", source) == "unreachable"


class TestRubyGems:
    def test_require_is_reachable(self):
        source = {"app.rb": "require 'nokogiri'\n"}
        assert check_reachability("RubyGems", "nokogiri", source) == "reachable"

    def test_hyphenated_gem_normalized(self):
        source = {"app.rb": "require 'factory_bot'\n"}
        assert check_reachability("RubyGems", "factory-bot", source) == "reachable"


class TestGo:
    def test_module_path_is_reachable(self):
        source = {"main.go": '\nimport (\n\t"github.com/pkg/errors"\n)\n'}
        assert check_reachability("Go", "github.com/pkg/errors", source) == "reachable"

    def test_unrelated_module_is_unreachable(self):
        source = {"main.go": '\nimport "fmt"\n'}
        assert check_reachability("Go", "github.com/pkg/errors", source) == "unreachable"


class TestMaven:
    def test_group_id_prefix_is_reachable(self):
        # groupId をJavaパッケージ名プレフィックスとして扱うヒューリスティックが
        # 成立する組み合わせ（groupId がそのままJavaパッケージ名の先頭と一致するケース）
        source = {"App.java": "import org.apache.commons.lang3.StringUtils;\n"}
        assert check_reachability(
            "Maven", "org.apache.commons:commons-lang3", source,
        ) == "reachable"

    def test_unrelated_group_is_unreachable(self):
        source = {"App.java": "import java.util.List;\n"}
        assert check_reachability(
            "Maven", "org.apache.commons:commons-lang3", source,
        ) == "unreachable"


class TestCratesIo:
    def test_use_statement_is_reachable(self):
        source = {"src/main.rs": "use serde_json::Value;\n"}
        assert check_reachability("crates.io", "serde-json", source) == "reachable"

    def test_extern_crate_is_reachable(self):
        source = {"src/main.rs": "extern crate serde_json;\n"}
        assert check_reachability("crates.io", "serde_json", source) == "reachable"


class TestPackagist:
    def test_use_statement_is_reachable(self):
        source = {"src/App.php": "use GuzzleHttp\\Client;\n"}
        assert check_reachability("Packagist", "guzzlehttp/guzzle", source) == "reachable"

    def test_unrelated_namespace_is_unreachable(self):
        source = {"src/App.php": "use Symfony\\Component\\HttpFoundation\\Request;\n"}
        assert check_reachability("Packagist", "guzzlehttp/guzzle", source) == "unreachable"


class TestHex:
    def test_alias_pascalcase_module_is_reachable(self):
        source = {"lib/app.ex": "alias EctoSql.Migrator\n"}
        assert check_reachability("Hex", "ecto_sql", source) == "reachable"

    def test_unrelated_module_is_unreachable(self):
        source = {"lib/app.ex": "import Phoenix.Controller\n"}
        assert check_reachability("Hex", "ecto_sql", source) == "unreachable"


class TestNuGet:
    def test_using_statement_is_reachable(self):
        source = {"Program.cs": "using Newtonsoft.Json;\n"}
        assert check_reachability("NuGet", "Newtonsoft.Json", source) == "reachable"

    def test_unrelated_namespace_is_unreachable(self):
        source = {"Program.cs": "using System;\n"}
        assert check_reachability("NuGet", "Newtonsoft.Json", source) == "unreachable"
