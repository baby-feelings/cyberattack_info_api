import { KeyRound, Package, ScanSearch, ShieldAlert, type LucideIcon } from 'lucide-react'
import type { AlertIconName } from './postureConfig'

// 設定（postureConfig）が持つアイコンの名前を、lucide-react のアイコンに対応づける（描く側の責務）
const ICONS: Record<AlertIconName, LucideIcon> = {
  KeyRound,
  Package,
  ScanSearch,
  ShieldAlert,
}

export function AlertKindIcon({ name, size = 14 }: { name: AlertIconName; size?: number }) {
  const Icon = ICONS[name]
  // 意味は隣の文字（種類の名前）で伝えるため、アイコンは装飾
  return <Icon size={size} aria-hidden="true" className="text-slate-400 shrink-0" />
}
