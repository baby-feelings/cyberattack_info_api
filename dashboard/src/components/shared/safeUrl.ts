// 外部データ（JVN・OSV の参照 URL など）をリンク（<a href>）にするときの URL 検査。
//
// `javascript:` や `data:` などの URL をそのまま href に入れると、クリックしたときにスクリプトが
// 実行される（XSS）。IPA「安全なウェブサイトの作り方」5-(ii) に従い、`http://`・`https://` で
// 始まる URL だけをリンクにする。React は href の中身を検査しないため、自前で検査する。

// リンクにしてよい URL ならそのまま返し、そうでなければ undefined を返す
export function safeHttpUrl(url: string | null | undefined): string | undefined {
  if (!url) return undefined
  try {
    // 絶対 URL でなければ（相対 URL・不正な文字列）例外になり、リンクにしない
    const { protocol } = new URL(url)
    return protocol === 'https:' || protocol === 'http:' ? url : undefined
  } catch {
    return undefined
  }
}
