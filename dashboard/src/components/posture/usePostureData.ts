import { useCallback, useEffect, useState } from 'react'
import {
  fetchGithubAlerts, fetchRepoAudit, fetchSiteMonitor, UnauthorizedError, type OperatingStatus,
} from '../../api/client'
import { AlertList } from './model/AlertList'
import { AuditMatrix } from './model/AuditMatrix'
import { SiteCheck } from './model/SiteCheck'
import { POSTURE_TEXT } from './postureConfig'

// 1つの取得元の状態。3つの取得元は、独立している（1つ失敗しても、ほかは、表示できる）
export type Source<T> =
  | { status: 'loading' }
  | { status: 'ready'; value: T }
  // message は、API のエラー文（画面には出さず、詳細として添える）。unauthorized は、セッションが無効・期限切れ（401）
  | { status: 'error'; message: string; unauthorized: boolean }

export type PostureSourceKey = 'audit' | 'alerts' | 'sites'

type Loader<T> = (authToken: string, operating: OperatingStatus) => Promise<T>

// 取得元ごとの読み込み。API の生データを、ドメインのクラスに包んで返す
const loadAudit: Loader<AuditMatrix> = async (authToken, operating) =>
  AuditMatrix.fromResponse(await fetchRepoAudit({ operating, authToken }))

const loadAlerts: Loader<AlertList> = async (authToken, operating) =>
  AlertList.fromResponse(await fetchGithubAlerts({ operating, authToken }))

const loadSites: Loader<SiteCheck[]> = async (authToken, operating) =>
  (await fetchSiteMonitor({ operating, authToken })).data.map((raw) => new SiteCheck(raw))

// 1つの取得元を、読み込み・再読み込みする。トークン・運用状態が変わったら、取り直す。
// 結果には、取得したときの条件（key）を添える。条件が変わった直後は、古い結果を出さず、読み込み中にする。
function useSource<T>(load: Loader<T>, authToken: string, operating: OperatingStatus) {
  const [attempt, setAttempt] = useState(0)
  const [result, setResult] = useState<{ key: string; source: Source<T> } | null>(null)
  const key = `${authToken}|${operating}|${attempt}`

  useEffect(() => {
    let cancelled = false
    load(authToken, operating)
      .then((value) => { if (!cancelled) setResult({ key, source: { status: 'ready', value } }) })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : POSTURE_TEXT.fetchFailed
        const unauthorized = error instanceof UnauthorizedError
        if (!cancelled) setResult({ key, source: { status: 'error', message, unauthorized } })
      })
    return () => { cancelled = true }
  }, [load, authToken, operating, key])

  const reload = useCallback(() => setAttempt((n) => n + 1), [])
  const source: Source<T> = result?.key === key ? result.source : { status: 'loading' }
  return { source, reload }
}

// 取得元ごとのフック。1つの取得元だけを使う画面（小タブ）が、単独で呼ぶ
export const useAuditSource = (authToken: string, operating: OperatingStatus) =>
  useSource(loadAudit, authToken, operating)
export const useAlertsSource = (authToken: string, operating: OperatingStatus) =>
  useSource(loadAlerts, authToken, operating)
export const useSitesSource = (authToken: string, operating: OperatingStatus) =>
  useSource(loadSites, authToken, operating)

// 3つの取得元（設定の監査・アラート・外形監視）を、並行に、独立に取る。
export function usePostureData(authToken: string, operating: OperatingStatus) {
  const { source: audit, reload: reloadAudit } = useAuditSource(authToken, operating)
  const { source: alerts, reload: reloadAlerts } = useAlertsSource(authToken, operating)
  const { source: sites, reload: reloadSites } = useSitesSource(authToken, operating)

  // 取得元を指定すれば、その1つだけ。省略すれば、3つとも
  const reload = useCallback((which?: PostureSourceKey) => {
    if (!which || which === 'audit') reloadAudit()
    if (!which || which === 'alerts') reloadAlerts()
    if (!which || which === 'sites') reloadSites()
  }, [reloadAudit, reloadAlerts, reloadSites])

  return { audit, alerts, sites, reload }
}
