"""パッケージ間の依存の向きのルール（リファクタリングで整えた構成を保つための検査）。

`import` 文を静的に読み、禁止された向きの依存が入っていないことを確認する。
ルールを破る変更を入れると、レビューを待たずにこのテストが失敗する。
"""
import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"

# 個別のドメイン（`core` は、これらを知らない）
_DOMAINS = ("kev", "osv", "jvn", "depscan", "depsops", "codescan", "mcp_server", "zapscan")

# (呼び出し元パッケージ, 依存してはいけないパッケージ, 理由)
FORBIDDEN: list[tuple[str, str, str]] = [
    ("auth", "mcp_server", "auth は mcp_server を知らない（登録口 auth.external_login を使う）"),
    # ドメイン同士は GitHub クライアントを共有する（core/github）
    ("codescan", "depscan", "CODESCAN は DEPSCAN に依存しない（共通部分は core/github）"),
    ("depsops", "depscan", "DEPSOPS は DEPSCAN に依存しない（共通部分は core/github）"),
    # 基盤は、個別のドメインを知らない（複数ドメインを束ねる処理は jobs/・taxii/ にある）
    *[
        ("core", domain, f"core は {domain} を知らない（束ねる処理は jobs/・taxii/）")
        for domain in _DOMAINS
    ],
    ("core", "jobs", "core は jobs を知らない"),
    ("core", "taxii", "core は taxii を知らない"),
]

# core が auth / crawler_logs を import してよいファイル（理由つきの例外）
CORE_EXCEPTIONS: dict[tuple[str, str], str] = {
    # 通知の送信先（登録ユーザーの Webhook）の解決に、アカウントの保存先を使う（遅延 import）
    ("app/core/notifications/recipients.py", "app.auth"): "送信先は登録ユーザーから解決する",
    # クローラーの実行結果を crawler_logs に記録する（実行基盤と記録は一体）
    ("app/core/crawler_runner.py", "app.crawler_logs"): "実行基盤は実行ログを記録する",
}


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    return modules


def _violations(source: str, forbidden: str) -> list[str]:
    found: list[str] = []
    for path in sorted((APP / source).rglob("*.py")):
        for module in _imported_modules(path):
            if module == f"app.{forbidden}" or module.startswith(f"app.{forbidden}."):
                found.append(f"{path.relative_to(APP.parent).as_posix()} -> {module}")
    return found


def test_package_dependency_rules():
    problems = [
        f"[{reason}] {line}"
        for source, forbidden, reason in FORBIDDEN
        for line in _violations(source, forbidden)
    ]
    assert not problems, "依存の向きのルール違反:\n" + "\n".join(problems)


def test_core_depends_on_auth_and_crawler_logs_only_where_documented():
    """core が auth / crawler_logs を import してよいのは、理由つきで列挙したファイルだけ。"""
    allowed = {file for (file, _pkg) in CORE_EXCEPTIONS}
    problems = []
    for forbidden in ("auth", "crawler_logs"):
        for line in _violations("core", forbidden):
            if line.split(" -> ")[0] not in allowed:
                problems.append(line)
    assert not problems, "core が想定外のパッケージに依存しています:\n" + "\n".join(problems)


def test_documented_exceptions_still_exist():
    """例外が不要になったら（依存が消えたら）、例外の記述も消すこと。"""
    stale = []
    for file, package in CORE_EXCEPTIONS:
        modules = _imported_modules(APP.parent / file)
        if not any(m == package or m.startswith(package + ".") for m in modules):
            stale.append(f"{file} -> {package}")
    assert not stale, "不要になった例外があります:\n" + "\n".join(stale)


def test_the_checker_detects_a_violation(tmp_path, monkeypatch):
    """検査自体が機能していること（違反を実際に見つける）。"""
    pkg = tmp_path / "app" / "auth"
    pkg.mkdir(parents=True)
    (pkg / "x.py").write_text("from app.mcp_server.models import McpToken\n", encoding="utf-8")
    monkeypatch.setattr("tests.test_dependency_rules.APP", tmp_path / "app")
    assert _violations("auth", "mcp_server") == ["app/auth/x.py -> app.mcp_server.models"]
