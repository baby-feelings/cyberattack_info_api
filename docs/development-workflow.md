# 開発の進め方（ブランチ・PR・コミット規約）

CLAUDE.md（常時読み込まれる）の行数を抑えるため、定型の手順をここに分離した。

## 開発手順

```bash
# 1. feature ブランチを作成
git checkout -b feature/your-feature-name

# 2. コードを変更・コミット
git add <files>
git commit -m "feat: 機能の説明"

# 3. プッシュして PR を作成
git push -u origin feature/your-feature-name

# 4. CI（ruff・mypy・pytest）が通ったら main へマージ
```

## コミットメッセージ規約

| プレフィックス | 用途 |
|--------------|------|
| `feat:` | 新機能 |
| `fix:` | バグ修正 |
| `docs:` | ドキュメント |
| `refactor:` | リファクタリング |
| `test:` | テスト追加・修正 |
| `chore:` | ビルド・設定変更 |

## 品質チェック（PR 時に CI が実行）

| チェック | 内容 |
|---------|------|
| ruff（`S`=bandit 相当を含む）・mypy | 静的解析・セキュリティ系の静的解析（`pyproject.toml`） |
| pytest（カバレッジ 90% 未満で失敗） | バックエンドのテスト |
| ESLint（`--max-warnings` の上限超過で失敗）・tsc・Vitest・Playwright | ダッシュボード |
| gitleaks（`gitleaks.yml`） | コミット範囲のシークレット検出 |
| Semgrep（`semgrep.yml`） | 静的解析（`p/security-audit`・`p/secrets`。CODESCAN と同じルール。検出があれば失敗） |
| Migration（`migration-check.yml`） | PostgreSQL で `upgrade head`・`alembic check`（モデルとのずれ）・`downgrade -1`・再 `upgrade`（`alembic/`・`models.py` の変更時） |
| OSV-Scanner（`osv-scanner-pr.yml`） | 新規導入された依存の脆弱性 |

**実行条件（ソースの更新があるときだけ）**: `ci.yml` は先頭の `changes` ジョブで変更ファイルを判定し、
バックエンド（`app/`・`tests/`・`alembic/`・`deploy/zap/`・依存・`pyproject.toml`・`Dockerfile` 等）の変更が
なければ `test` を、`dashboard/` の変更がなければ `dashboard-test`・`dashboard-e2e` を省略する
（`ci.yml` 自体の変更時は両方実行）。Semgrep はドキュメント（`*.md`・`docs/`・`.claude/skills/`）のみの
変更で実行しない。**gitleaks・OSV-Scanner は絞らない**（ドキュメントや設定にもシークレット・依存が入りうる）。
省略はワークフロー単位でなくジョブ単位（将来「必須チェック」を設定しても、省略されたジョブは成功扱い）。
ダッシュボードの Vercel デプロイ（`deploy.yml`）は従来から `dashboard/**` の変更時のみ、Vercel のプレビュー
ビルドは `dashboard/vercel.json` の `ignoreCommand` で、ダッシュボードに差分がなければスキップする。

定期実行: pip-audit・OSV-Scanner（毎週）、OWASP ZAP（毎週月曜 03:00 JST。`docs/zap-scan.md`）、
DEPSCAN/CODESCAN（毎日）。
