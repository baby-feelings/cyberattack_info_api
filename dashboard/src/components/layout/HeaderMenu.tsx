import { useEffect, useRef, useState } from 'react'
import { Menu } from 'lucide-react'

// ハンバーガーメニュー（Issue #227: 設定画面への導線）
export function HeaderMenu({ onOpenSettings }: { onOpenSettings: () => void }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  // メニュー外のクリック・Escapeキーで閉じる。全画面の透明オーバーレイ方式だと、
  // 親ヘッダーの backdrop-blur が fixed の基準になりヘッダー内しか覆えなかったため、
  // ドキュメント全体のイベントで判定する
  useEffect(() => {
    if (!menuOpen) return
    function handlePointerDown(e: PointerEvent) {
      if (!menuRef.current?.contains(e.target as Node)) setMenuOpen(false)
    }
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('pointerdown', handlePointerDown)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [menuOpen])

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setMenuOpen((v) => !v)}
        aria-label="メニュー"
        aria-expanded={menuOpen}
        className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
      >
        <Menu size={18} />
      </button>
      {menuOpen && (
        <div className="absolute right-0 top-full mt-1 z-20 w-40 rounded-lg border border-slate-800 bg-slate-900 shadow-xl py-1">
          <button
            onClick={() => { setMenuOpen(false); onOpenSettings() }}
            className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 transition-colors"
          >
            設定
          </button>
        </div>
      )}
    </div>
  )
}
