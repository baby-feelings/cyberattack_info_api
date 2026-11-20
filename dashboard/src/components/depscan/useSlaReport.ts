import { useEffect, useState } from 'react'
import { fetchSlaReport, type OperatingStatus, type SlaReport } from '../../api/client'

// 取得結果。どの運用状態で取得したかを持ち、現在の条件と違えば「取得中」とみなす
interface Result {
  operating: OperatingStatus
  // 取得したときの「再読み込みの回数」。現在の回数と違えば「取得中」とみなす
  attempt: number
  report: SlaReport | null
}

// 対応状況（SLA）の取得と、運用状態の切り替え。画面（SlaPanel）は、結果を描くだけにする
export function useSlaReport(authToken?: string) {
  const [operating, setOperating] = useState<OperatingStatus>('active')
  const [result, setResult] = useState<Result | null>(null)
  // 再読み込みのボタンを押すたびに増やし、取り直す
  const [attempt, setAttempt] = useState(0)

  // 運用状態が変わるたびに取り直す。状態の更新は取得の完了時だけ行う
  // （条件の変更で古い取得が遅れて届いても、結果を捨てる）
  useEffect(() => {
    let cancelled = false
    fetchSlaReport(authToken, operating)
      .then(report => { if (!cancelled) setResult({ operating, attempt, report }) })
      .catch(() => { if (!cancelled) setResult({ operating, attempt, report: null }) })
    return () => { cancelled = true }
  }, [authToken, operating, attempt])

  const loading = result === null || result.operating !== operating || result.attempt !== attempt
  // report が null で loading でなければ、取得に失敗している
  const report = !loading && result ? result.report : null
  const reload = () => setAttempt(n => n + 1)
  return { operating, setOperating, loading, report, reload }
}
