// 「態勢」タブの設定。文言・配色を、ここに1か所だけ置く（コンポーネントに直書きしない）。
// 点検項目の名前・直し方は、ここに持たない（API が返す `label`・`fix` を使う）。

import type { AuditStatusKind } from './model/AuditStatus'

// 点検項目の状態ごとの表示。色だけに頼らず、記号と文言でも示す（色覚・モノクロでも読めるように）
export const AUDIT_STATUS_VIEW: Record<AuditStatusKind, { label: string; glyph: string; cls: string }> = {
  ok: { label: '合格', glyph: '✓', cls: 'bg-emerald-950 text-emerald-300 border-emerald-800' },
  ng: { label: '不合格', glyph: '✕', cls: 'bg-red-950 text-red-300 border-red-800' },
  unavailable: { label: '取得不可', glyph: '－', cls: 'bg-slate-800 text-slate-400 border-slate-700' },
  not_enforceable: { label: '強制できない', glyph: '－', cls: 'bg-slate-800 text-slate-400 border-slate-700' },
}
