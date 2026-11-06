// 「最終取得」表示の設定。しきい値・文言・色・更新間隔を、ここに1か所だけ置く（コンポーネントに直書きしない）。

// 取得状況を表示するクローラーの種別（バックエンドの crawler_logs.crawler_type と同じ値）
export type FetchedCrawlerType = 'KEV' | 'OSV' | 'JVN' | 'DEPSCAN' | 'CODESCAN' | 'DEPSOPS' | 'RUNTIME'

// 状態。fresh=最新、stale=更新が遅れている、failed=直近の実行が失敗、unknown=実行記録を取得できない
// モーダル画面ごとの取得元。画面側に種別を直書きせず、ここに1か所だけ置く。
// 依存パッケージ・対応状況は、DEPSCAN の実行で保存・集計したデータを表示する
export const SCREEN_FETCH_SOURCE = {
  dependencies: 'DEPSCAN',
  sla: 'DEPSCAN',
  depsops: 'DEPSOPS',
  runtimes: 'RUNTIME',
} as const satisfies Record<string, FetchedCrawlerType>

export type FreshnessState = 'fresh' | 'stale' | 'failed' | 'unknown'

// 環境変数（ビルド時）の数値を読む。未設定・不正な値（数値でない・0以下）は既定値を使う
export function numberFromEnv(raw: string | undefined, fallback: number): number {
  const value = Number(raw)
  return raw !== undefined && raw !== '' && Number.isFinite(value) && value > 0 ? value : fallback
}

// クローラーの実行間隔（時間）。バックエンドは毎日1回実行する
export const CRAWL_INTERVAL_HOURS = numberFromEnv(import.meta.env.VITE_CRAWL_INTERVAL_HOURS, 24)
// 実行の遅れを許す余裕（時間）。GitHub Actions の補完 cron が数時間遅れることがあるため
export const STALE_GRACE_HOURS = numberFromEnv(import.meta.env.VITE_STALE_GRACE_HOURS, 6)
// この時間を超えて成功していなければ「遅れている」とする
export const STALE_AFTER_HOURS = CRAWL_INTERVAL_HOURS + STALE_GRACE_HOURS

// 実行履歴から、最新の実行と最後の成功を探すために読む件数（最後の成功が直近の失敗の先にある場合に備える）
export const LOG_LOOKBACK = 10
// 相対時間の表示を更新する間隔（ミリ秒）
export const TICK_MS = 60_000
// 実行履歴を取り直す間隔（ミリ秒）
export const REFETCH_MS = 10 * 60_000

// 日時・相対時間の表示ロケール。タイムゾーンは、閲覧者のブラウザの設定に従う（固定しない）
export const DISPLAY_LOCALE = 'ja-JP'

// 表示する文言。状態の判別を色だけに頼らないため、状態ごとの文言を持つ
export const FRESHNESS_TEXT = {
  label: '最終取得',
  stale: '更新が遅れています',
  failed: '直近の実行が失敗',
  lastSuccess: '最終成功',
  unknown: '取得状況を確認できません',
  noChange: '変化なし',
  inserted: (count: number) => `新規 ${count} 件`,
  updated: (count: number) => `更新 ${count} 件`,
} as const

// 状態ごとの見た目（Tailwind のクラス）。異常のときだけ点を脈打たせる（動きを減らす設定では止める）
export const FRESHNESS_STYLE: Record<FreshnessState, { dot: string; text: string }> = {
  fresh: { dot: 'bg-emerald-400', text: 'text-slate-300' },
  stale: { dot: 'bg-amber-400 motion-safe:animate-pulse', text: 'text-amber-300' },
  failed: { dot: 'bg-red-400 motion-safe:animate-pulse', text: 'text-red-300' },
  unknown: { dot: 'bg-slate-600', text: 'text-slate-500' },
}
