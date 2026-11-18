// 「態勢」タブの設定。文言・配色を、ここに1か所だけ置く（コンポーネントに直書きしない）。
// 点検項目の名前・直し方は、ここに持たない（API が返す `label`・`fix` を使う）。

import type { AuditStatusKind } from './model/AuditStatus'

// ── 文言 ───────────────────────────────────────────────────────

export const POSTURE_TEXT = {
  // 取得に失敗したが、理由を読み取れないときの文言
  fetchFailed: '取得できませんでした',
  loginDescription: 'ログインすると、自分のリポジトリのアラート・設定の監査・外形監視の結果を閲覧できます',
  retry: '再試行',
  loadFailed: '読み込めませんでした',
  loading: '読み込み中',
  all: 'すべて',
  summary: {
    openAlerts: 'アラート（未対応）',
    auditRate: '設定の達成率（%）',
    siteIssues: '外形監視の問題',
    unknownPrefix: '取得できなかった項目:',
  },
  // 3つの取得元の名前（見出しの「取得できなかった項目」に出す）
  sources: { alerts: 'アラート', audit: '設定の監査', sites: '外形監視' },
  audit: {
    title: 'リポジトリ × 点検項目',
    repoColumn: 'リポジトリ',
    onlyIssues: '改善が必要なものだけ',
    search: 'リポジトリ名で検索',
    empty: '点検の結果がありません。リポジトリ設定の監査は、毎日の取得のあとに表示されます。',
    noIssues: '改善が必要なリポジトリはありません。',
    noMatch: '該当するリポジトリがありません。',
    legend: '項目を押すと、詳細と直し方が出ます',
    detail: '詳細',
    fix: '直し方',
  },
  alerts: {
    title: 'GitHub のセキュリティアラート',
    kind: '種類',
    severity: '重要度',
    empty: '未対応のアラートはありません。',
    unavailableTitle: '取得できなかった項目（機能が無効・権限不足）',
    unknownReason: '理由不明',
    columns: { severity: '重要度', kind: '種類', repo: 'リポジトリ', title: 'タイトル', tool: '検知元' },
    opensInNewTab: '（新しいタブで開く）',
  },
  sites: {
    title: '公開サイトの外形監視',
    empty: '外形監視の結果がありません。',
    columns: { url: 'URL', tls: 'TLS 残日数', findings: '指摘' },
    tlsUnit: '日',
    noFindings: '問題なし',
  },
}

// 外形監視の指摘の、重要度ごとの表示（API の値）。色だけに頼らず、記号でも示す
export const SITE_SEVERITY_VIEW: Record<string, { glyph: string; cls: string }> = {
  ERROR: { glyph: '✕', cls: 'text-red-300' },
  WARNING: { glyph: '▲', cls: 'text-amber-300' },
  INFO: { glyph: '・', cls: 'text-slate-400' },
}

// ── アラートの種類 ──────────────────────────────────────────────

// アイコンは、名前で持ち（lucide-react のコンポーネントを、ここで import しない）、描く側が対応づける
export type AlertIconName = 'KeyRound' | 'Package' | 'ScanSearch' | 'ShieldAlert'
export interface AlertKindView { label: string; icon: AlertIconName }

// API の種類（secret / dependabot / code）ごとの表示
export const ALERT_KIND_VIEW: Record<'secret' | 'dependabot' | 'code', AlertKindView> = {
  secret: { label: 'シークレット', icon: 'KeyRound' },
  dependabot: { label: 'Dependabot', icon: 'Package' },
  code: { label: 'コード', icon: 'ScanSearch' },
}
// 未知の種類のアイコン
export const ALERT_FALLBACK_ICON: AlertIconName = 'ShieldAlert'

// 重要度の順位（小さいほど重大）。API は、重要度を大文字にして返す。未知・未設定は、最後
export const ALERT_SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
export const ALERT_UNKNOWN_SEVERITY_RANK = Object.keys(ALERT_SEVERITY_RANK).length

// 重要度のバッジの配色（`SeverityBadge` の classMap に渡す）
export const ALERT_SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'bg-red-950 text-red-300 border-red-800',
  HIGH: 'bg-orange-950 text-orange-300 border-orange-800',
  MEDIUM: 'bg-amber-950 text-amber-300 border-amber-800',
  LOW: 'bg-slate-800 text-slate-300 border-slate-700',
}

// ── 設定の監査 ──────────────────────────────────────────────────

// 点検項目の状態ごとの表示。色だけに頼らず、記号と文言でも示す（色覚・モノクロでも読めるように）
export const AUDIT_STATUS_VIEW: Record<AuditStatusKind, { label: string; glyph: string; cls: string }> = {
  ok: { label: '合格', glyph: '✓', cls: 'bg-emerald-950 text-emerald-300 border-emerald-800' },
  ng: { label: '不合格', glyph: '✕', cls: 'bg-red-950 text-red-300 border-red-800' },
  unavailable: { label: '取得不可', glyph: '－', cls: 'bg-slate-800 text-slate-400 border-slate-700' },
  not_enforceable: { label: '強制できない', glyph: '－', cls: 'bg-slate-800 text-slate-400 border-slate-700' },
}
