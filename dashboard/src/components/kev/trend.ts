import type { MonthlyStat } from '../../api/client'

// 月別トレンドに出す月数。OSV・JVN（直近180日）に合わせ、3画面とも直近6ヶ月で統一する
export const TREND_MONTHS = 6

// 月別の件数のうち、新しい側の n か月分だけを返す（年月の昇順に並んでいる前提。並びは崩さない）
export function recentMonths(trend: MonthlyStat[], months = TREND_MONTHS): MonthlyStat[] {
  return months > 0 ? trend.slice(-months) : []
}
