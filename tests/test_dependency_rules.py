"""パッケージ間の依存の向きのルール（リファクタリングで整えた構成を保つための検査）。

`import` 文を静的に読み、禁止された向きの依存が入っていないことを確認する。
ルールを破る変更を入れると、レビューを待たずにこのテストが失敗する。
"""
import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"

# (呼び出し元パッケージ, 依存してはいけないパッケージ, 理由)
FORBIDDEN: list[tuple[str, str, str]] = [
    ("auth", "mcp_server", "auth は mcp_server を知らない（登録口 auth.external_login を使う）"),
    # ドメイン同士は GitHub クライアントを共有する（core/github）
    ("codescan", "depscan", "CODESCAN は DEPSCAN に依存しない（共通部分は core/github）"),
    ("depsops", "depscan", "DEPSOPS は DEPSCAN に依存しない（共通部分は core/github）"),
]


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
                found.append(f"{path.relative_to(APP.parent)} -> {module}")
    return found


def test_package_dependency_rules():
    problems = [
        f"[{reason}] {line}"
        for source, forbidden, reason in FORBIDDEN
        for line in _violations(source, forbidden)
    ]
    assert not problems, "依存の向きのルール違反:\n" + "\n".join(problems)


def test_the_checker_detects_a_violation(tmp_path, monkeypatch):
    """検査自体が機能していること（違反を実際に見つける）。"""
    pkg = tmp_path / "app" / "auth"
    pkg.mkdir(parents=True)
    (pkg / "x.py").write_text("from app.mcp_server.models import McpToken\n", encoding="utf-8")
    monkeypatch.setattr("tests.test_dependency_rules.APP", tmp_path / "app")
    assert _violations("auth", "mcp_server") == ["app\\auth\\x.py -> app.mcp_server.models"] or \
        _violations("auth", "mcp_server") == ["app/auth/x.py -> app.mcp_server.models"]
