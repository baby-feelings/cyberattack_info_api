import { useEffect, useState } from 'react'
import { fetchSlaReport, type OperatingStatus, type SlaReport } from '../../api/client'

// 取得結果。どの運用状態で取得したかを持ち、現在の条件と違えば「取得中」とみなす
interface Result {
  operating: OperatingStatus
  report: SlaReport | null
}

// 対応状況（SLA）の取得と、運用状態の切り替え。画面（SlaPanel）は、結果を描くだけにする
export function useSlaReport(authToken?: string) {
  const [operating, setOperating] = useState<OperatingStatus>('active')
  const [result, setResult] = useState<Result | null>(null)

  // 運用状態が変わるたびに取り直す。状態の更新は取得の完了時だけ行う
  // （条件の変更で古い取得が遅れて届いても、結果を捨てる）
  useEffect(() => {
    let cancelled = false
    fetchSlaReport(authToken, operating)
      .then(report => { if (!cancelled) setResult({ operating, report }) })
      .catch(() => { if (!cancelled) setResult({ operating, report: null }) })
    return () => { cancelled = true }
  }, [authToken, operating])

  const loading = result === null || result.operating !== operating
  // report が null で loading でなければ、取得に失敗している
  const report = !loading && result ? result.report : null
  return { operating, setOperating, loading, report }
}
