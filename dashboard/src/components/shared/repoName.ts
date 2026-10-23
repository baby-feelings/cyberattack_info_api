// "owner/repo" から repo 名だけを取り出す（アプリ一覧では owner を省いて見やすくする）
export function repoShortName(repoFullName: string): string {
  return repoFullName.split('/')[1] ?? repoFullName
}
