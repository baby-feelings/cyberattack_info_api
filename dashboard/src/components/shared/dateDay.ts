// 一覧の日付の区切りに使う、日の表示と比較。行に表示する日付（toLocaleDateString('ja-JP')）と
// 同じ基準で日を比べるため、区切りと行の日付がずれない。

export function formatDay(date: string): string {
  return new Date(date).toLocaleDateString('ja-JP', { year: 'numeric', month: 'long', day: 'numeric' })
}

// 直前の行と日が変わったか（先頭の行は常に true）。一覧が日付順に並んでいるときだけ意味を持つ
export function isNewDay(prev: string | undefined, current: string): boolean {
  return prev === undefined || formatDay(prev) !== formatDay(current)
}
