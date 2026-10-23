import { useCallback, useState } from 'react'

// 自分が使っている製品名などのキーワード（KEV・OSV・JVN で共通）。ブラウザ内に保存するため、
// 端末をまたぐと別になる。サーバーには送らない
const STORAGE_KEY = 'watch_keywords'
export const MAX_KEYWORDS = 10
export const MAX_KEYWORD_LENGTH = 40

function readStored(): string[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]')
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter((v): v is string => typeof v === 'string' && v.trim() !== '' && v.length <= MAX_KEYWORD_LENGTH)
      .slice(0, MAX_KEYWORDS)
  } catch {
    // 保存領域が使えない・壊れている場合は、キーワードなしとして扱う
    return []
  }
}

function writeStored(keywords: string[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(keywords))
  } catch {
    // 保存できなくても、画面上では使える（再読み込みで消えるだけ）
  }
}

export function useWatchKeywords() {
  const [keywords, setKeywords] = useState<string[]>(readStored)

  // 追加に失敗したときは、理由（画面に出す文言）を返す。成功は null
  const add = useCallback((raw: string): string | null => {
    const keyword = raw.trim()
    if (keyword === '') return 'キーワードを入力してください'
    if (keyword.length > MAX_KEYWORD_LENGTH) return `キーワードは${MAX_KEYWORD_LENGTH}文字までです`
    if (keywords.some(k => k.toLowerCase() === keyword.toLowerCase())) return 'すでに登録されています'
    if (keywords.length >= MAX_KEYWORDS) return `登録できるのは${MAX_KEYWORDS}個までです`
    const next = [...keywords, keyword]
    setKeywords(next)
    writeStored(next)
    return null
  }, [keywords])

  const remove = useCallback((keyword: string) => {
    const next = keywords.filter(k => k !== keyword)
    setKeywords(next)
    writeStored(next)
  }, [keywords])

  return { keywords, add, remove }
}
