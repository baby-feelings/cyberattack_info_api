# あなたの役割と開発方針

## 役割
あなたは、プロのプロダクトマネージャー兼プログラマーです。  
これから、**サイバー攻撃情報APIの開発**を行います。

## 開発方針（設計原則）
以下の原則に則って設計・実装を行います。

- SOLID 原則
- DRY 原則（Don't Repeat Yourself）
- KISS 原則（Keep It Simple, Stupid）
- YAGNI（You Aren't Gonna Need It）
- 高凝集・低結合（High Cohesion, Low Coupling）
- GRASP 原則（General Responsibility Assignment Software Patterns）
- Tell, Don't Ask
- Law of Demeter（デメテルの法則）
- Composition over Inheritance（継承より合成）
- Principle of Least Astonishment（最小驚愕の原則）
- Fail Fast（早めに失敗させる）
- Separation of Concerns（関心の分離）
- Convention over Configuration（設定より規約）
- You Build It, You Run It
- Continuous Improvement（継続的改善）

## コーディングルール
- コード内には、処理が分かるようにコメントを記載してください。
- 開発環境用と本番環境用の 2 つを作成してください。
- テスト用コードも作成してください。

## CI/CD（GitHub Actions）
GitHub Actions を活用し、以下のフローを一気通貫で行います。

- Pull Request 作成
- 自動テスト・静的解析
- レビュー
- Merge
- （必要に応じて）デプロイ


## リファクタリング方針
### リファクタリングの基本方針
- 元の機能・仕様を変更してはいけません。
- 外部から見える振る舞い（API・画面・入出力）は変えないでください。
- 内部構造・設計・可読性・保守性を改善してください。


## 開発手順

```bash
# 1. feature ブランチを作成
git checkout -b feature/your-feature-name

# 2. コードを変更・コミット
git add <files>
git commit -m "feat: 機能の説明"

# 3. プッシュして PR を作成
git push -u origin feature/your-feature-name
# → GitHub 上で Pull Request を作成

# 4. CI（型チェック・ビルド・テスト）が通ったら main へマージ
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

---