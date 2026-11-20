# code-review-graph の使い方と、誤検知の見方

`code-review-graph`（https://github.com/tirth8205/code-review-graph）は、コードを構文解析して、関数・クラス・
呼び出しの関係をグラフにする。名前の一致で関係を推定するため、**リファクタリングのときに、誤検知が多く出る**。
2026-11-20 に、このリポジトリで原因を確認した。出力を、そのまま信じず、この文書に沿って読むこと。

## 誤検知の原因（確認済み）

| # | 原因 | 症状・確認した例 |
|---|------|----------------|
| 1 | 関数を「呼び出し」でなく、値として渡す使い方を追跡できない | `onClick={handleSave}`・`onSelect={handleOwner}`・`request_with_retry(_post_batch)`・`self.app(scope, receive, send_and_capture)` の関数が、「デッドコード」・呼び出し元 0 件になる |
| 2 | 継承の動的な呼び出しを追跡できない | 基底クラスが `self.build_message()` で呼ぶ、サブクラスの `build_message` が「デッドコード」。SDK が呼ぶ `authorize` など、Playwright のレポーターの `onEnd` も同じ |
| 3 | 無名の矢印関数（`.map(r => ...)`）を、引数名の関数として登録する | 「デッドコード」の約 7 割が、`o`・`e`・`r`・`rec`・`eco` などの名前。「影響を受ける流れ」にも、`rec`・`r` が出る。`callers_of` の呼び出し元にも出る |
| 4 | JSX での部品の使用が、深い階層で追跡されない | `ActionBadge`・`RepoBadge` などが、「テストなし」になる（1 つ上の階層の部品は「間接的にテスト済み」） |
| 5 | 「間接的にテスト済み」（`coverage: indirect`）も、警告に含める | テストで実行されている `_forking` などが、「Test coverage gaps」に出る（未テストは 0 件） |
| 6 | `changed_files` を指定しても、diff 全体の関数を返す | 5 ファイルを指定しても、指定していないファイルの関数が「変更された関数」に入る |
| 7 | グラフが古くなる | 更新は、ファイルの編集・コミットで動く。`git pull`・マージ・ブランチ切替では動かない（`head_matches_build: false`） |
| 8 | 呼び出しの約 73% が、名前だけの推定 | `CALLS` 28,324 件のうち、直接の対応づけは 7,628 件。`reload`・`update` など一般的な名前は、無関係な関数と混ざる |

## 結果の読み方

| ツール・出力 | 扱い |
|--------------|------|
| `refactor_tool` の `dead_code` | **原因 1〜3 のものは無視する。** 削除する前に、`grep` で、実際の使われ方（JSX のプロパティ・コールバック・基底クラスからの呼び出し）を確認する |
| `detect_changes_tool` の「テストなし」 | `coverage: indirect` は、問題ではない。TSX の部品（原因 4）は、`grep` とテストで確認する。**テストの有無は、`pytest --cov`・`vitest --coverage` を正とする** |
| `detect_changes_tool` の変更関数・フロー | 名前が 1〜2 文字の関数・フロー（原因 3）は、無視する。`changed_files` を指定したときは、範囲外の関数が混ざる（原因 6） |
| `query_graph_tool`（`callers_of` など） | **`resolution=direct` を使う**（名前の推定を除く）。結果が 0 件でも、値として渡されている場合がある（原因 1）。`resolution_split` と、`confidence` の注意書きを見る |
| `get_impact_radius_tool` | 一般的な名前（`update`・`reload` など）は、影響範囲が広く出る。`resolution=direct` の `callers_of` で絞る |

信頼できるのは、名前が一意な関数の、`resolution=direct` の呼び出し関係である。迷ったときは、`grep` で確かめる。

## 運用

- 作業の最初に、`code-review-graph build` と `code-review-graph watch`（バックグラウンド）を実行する。
- **`git pull`・マージ・ブランチの切り替えのあとは、`code-review-graph update` を実行する**（原因 7）。
  `watch` が動いていないと、グラフは、編集の反映も止まる。`get_minimal_context_tool` や
  `list_graph_stats_tool` の `_graph.head_matches_build` が `false` なら、更新が必要。
- `.code-review-graphignore` に、生成物（`dashboard/dist/**`・`playwright-report/**`・`coverage/**` など）を書いて、索引から除く。
- 再現例（Issue 用）: 原因 1 は `dashboard/src/components/SettingsPanel.tsx` の `handleSave`、原因 2 は
  `app/depscan/notifier.py` の `build_message`、原因 3 は `dashboard/src/components/depscan/RuntimesPanel.tsx` の `repos.map(r => ...)`。

## 代替・併用できるツール（試していない。導入前に最新の状況を確認する）

- 正確な参照の検索: Serena（言語サーバー〈LSP〉の MCP サーバー）。
- 未使用コード: knip（TypeScript）・vulture（Python）。
- テストの穴: カバレッジ（導入済み）・mutmut（Python）・Stryker（TypeScript）。
- 構造の一括書き換え: ast-grep。依存の向きの検査: import-linter（Python）・dependency-cruiser（TypeScript）。
