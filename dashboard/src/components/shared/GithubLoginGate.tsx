import type { ReactNode } from 'react'
import { LogIn, LogOut } from 'lucide-react'
import { githubLoginUrl } from '../../api/client'
import { useGithubSession, type GithubSession } from '../../hooks/useGithubSession'

// GitHub ログインのゲート（共通部品）。未ログインならログインの案内、ログイン済みなら本体を描く。
//
// セッション管理は、DEPSCAN・CODESCAN と共通の `useGithubSession` を使い、localStorage のキーも共有する
// （どのタブでログインしても、すべて閲覧できる）。DEPSCAN・CODESCAN のゲートは、同じ作りの重複が
// 既にあり、そちらは、この部品への置き換えを後続とする（今回は、新しいタブだけが使う）。
// 本体へ渡す操作。logout は、確認なしでログアウト扱いにする（セッション失効のとき用）。参照は安定している
export interface GateControls {
  logout: () => void
}

export function GithubLoginGate({ description, children }: {
  // 未ログイン時に、ログインで何が見られるようになるかの説明
  description: string
  // ログイン済みのときに描く本体。セッション（トークン）と、ログアウトの操作（セッション失効時に呼ぶ）を受け取る
  children: (session: GithubSession, controls: GateControls) => ReactNode
}) {
  const { session, checked, handleLogout, handleLogoutClick } = useGithubSession()

  if (!checked) return null

  if (!session) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 shadow-lg flex flex-col items-center gap-4 text-center">
        <LogIn size={32} className="text-slate-400" />
        <div>
          <p className="text-sm font-semibold text-white">GitHubアカウントでログインしてください</p>
          <p className="text-xs text-slate-500 mt-1">{description}</p>
        </div>
        <a
          href={githubLoginUrl()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm font-medium text-white transition-colors"
        >
          <LogIn size={16} />
          GitHubでログイン
        </a>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between text-xs text-slate-500">
        <span>
          ログイン中: <span className="text-slate-300 font-medium">{session.username}</span>
        </span>
        <button
          onClick={handleLogoutClick}
          className="flex items-center gap-1 text-slate-500 hover:text-slate-300 transition-colors"
        >
          <LogOut size={12} />
          ログアウト
        </button>
      </div>

      {children(session, { logout: handleLogout })}
    </div>
  )
}
