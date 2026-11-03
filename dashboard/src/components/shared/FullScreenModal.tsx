import { useEffect, type ReactNode } from 'react'
import { X, type LucideIcon } from 'lucide-react'

// 画面全体を覆うモーダルの共通の殻（ヘッダー・閉じるボタン・Esc で閉じる）。
// 依存パッケージ・言語・対応状況・Dependabot 運用状況のモーダルが、同じ作りを個別に持っていたため、
// 1か所にまとめる。呼び出し側は、開いているときだけ描画する（閉じている間は Esc を拾わない）
export function FullScreenModal({
  label, title, icon: Icon, maxWidth = 'max-w-6xl', onClose, children,
}: {
  // aria-label（アクセシブルな名前）。title を省略すると、見出しにも使う
  label: string
  title?: string
  icon: LucideIcon
  maxWidth?: 'max-w-5xl' | 'max-w-6xl'
  onClose: () => void
  children: ReactNode
}) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950 flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-label={label}
    >
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
          <Icon size={16} className="text-slate-400" />
          {title ?? label}
        </span>
        <button
          onClick={onClose}
          aria-label="閉じる"
          className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded"
        >
          <X size={18} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-5">
        <div className={`${maxWidth} mx-auto flex flex-col gap-5`}>
          {children}
        </div>
      </div>
    </div>
  )
}
