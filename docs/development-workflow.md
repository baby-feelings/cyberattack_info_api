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
| OSV-Scanner（`osv-scanner-pr.yml`） | 新規導入された依存の脆弱性 |

定期実行: pip-audit・OSV-Scanner（毎週）、OWASP ZAP（毎週月曜 03:00 JST。`docs/zap-scan.md`）、
DEPSCAN/CODESCAN（毎日）。
