// クローラー実行ログ（DEPSCAN 画面の新着データ検知に利用）関連の API クライアント。

import { apiFetch } from './shared'

export interface CrawlerLogOut {
  id: number
  crawler_type: string
  status: string
  started_at: string
  finished_at: string
  duration_seconds: number
  inserted: number
  updated: number
  deleted: number
  error_message: string | null
}

export async function fetchCrawlerLogs(params: {
  crawlerType?: string
  status?: string
  limit?: number
}): Promise<CrawlerLogOut[]> {
  const p = new URLSearchParams()
  if (params.crawlerType) p.set('crawler_type', params.crawlerType)
  if (params.status) p.set('status', params.status)
  p.set('limit', String(params.limit ?? 30))
  return apiFetch<CrawlerLogOut[]>(`/api/crawler-logs?${p}`)
}
