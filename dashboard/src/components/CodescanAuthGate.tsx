import { LogIn, LogOut } from 'lucide-react'
import { githubLoginUrl } from '../api/client'
import { useGithubSession } from '../hooks/useGithubSession'
import { CodescanPanel } from './CodescanPanel'

// CODESCAN タブの GitHub ログインゲート（Issue #219）。
//
// セッション管理（ログイン状態・トークン・OAuthコールバック処理）は DEPSCAN と
// 共通の useGithubSession を使い、localStorage のキーも共有するため、DEPSCAN/
// CODESCAN のどちらのタブでログインしても両方閲覧できる。DEPSCAN と異なり
// オンデマンドスキャンの概念が無いため、スキャン進捗ポーリングUIは不要で、
// ログイン確認ができたら即座に CodescanPanel を表示するシンプルな構成にしている。
export function CodescanAuthGate() {
  const { session, checked, handleLogoutClick } = useGithubSession()

  if (!checked) return null

  if (!session) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 shadow-lg flex flex-col items-center gap-4 text-center">
        <LogIn size={32} className="text-slate-400" />
        <div>
          <p className="text-sm font-semibold text-white">GitHubアカウントでログインしてください</p>
          <p className="text-xs text-slate-500 mt-1">
            ログインすると、自アプリのコード脆弱性診断結果を閲覧できます
          </p>
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

      <CodescanPanel authToken={session.token} />
    </div>
  )
}
