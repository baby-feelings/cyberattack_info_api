import { useEffect, useState } from 'react'

interface CountsState {
  // この件数を取得したときの countFor。条件（期間など）が変わったら古い件数を捨てるために持つ
  source: unknown
  values: Record<string, number | undefined>
}

// キーワードごとの該当件数を取得する。countFor は「そのキーワードの件数」を返す関数で、
// 期間などの条件が変わったら（countFor が作り直されたら）取り直す。
// 取得に失敗した・取得中のキーワードは undefined（画面では「—」と表示し、0 件と誤解させない）
export function useKeywordCounts(
  keywords: string[],
  countFor: (keyword: string) => Promise<number>,
): Record<string, number | undefined> {
  const [state, setState] = useState<CountsState>({ source: null, values: {} })

  useEffect(() => {
    let cancelled = false
    for (const keyword of keywords) {
      countFor(keyword)
        .then(n => {
          if (cancelled) return
          // 別の条件で取得した件数は引き継がない
          setState(prev => ({
            source: countFor,
            values: { ...(prev.source === countFor ? prev.values : {}), [keyword]: n },
          }))
        })
        .catch(() => { /* 失敗は「—」表示のまま */ })
    }
    // 条件が変わった後に、古い取得結果が上書きしないようにする
    return () => { cancelled = true }
  }, [keywords, countFor])

  // 現在の条件で取得した件数だけを返す（条件が変わった直後は、取得し直すまで「—」）
  return state.source === countFor ? state.values : {}
}
