import { formatDay } from './dateDay'

// 一覧の日付ごとの区切り行（例: 2026年10月20日）。KEV・OSV・JVN・DEPSCAN・CODESCAN で共通に使う
export function DateDividerRow({ date, colSpan }: { date: string; colSpan: number }) {
  return (
    <tr aria-label={`${formatDay(date)}の区切り`} data-divider>
      <td colSpan={colSpan} className="bg-slate-950/50 px-2 py-1 text-[11px] font-semibold text-slate-500">
        {formatDay(date)}
      </td>
    </tr>
  )
}
