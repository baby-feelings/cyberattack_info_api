// 「態勢」タブの設定。文言・配色を、ここに1か所だけ置く（コンポーネントに直書きしない）。
// 点検項目の名前・直し方は、ここに持たない（API が返す `label`・`fix` を使う）。

import type { AuditStatusKind } from './model/AuditStatus'

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
