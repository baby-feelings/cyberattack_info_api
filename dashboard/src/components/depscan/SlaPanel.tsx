import { Timer } from 'lucide-react'
import { PanelFrame } from '../shared/PanelFrame'
import { LastFetched } from '../freshness/LastFetched'
import { SCREEN_FETCH_SOURCE } from '../freshness/freshnessConfig'
import { TableLoadingSkeleton, EmptyState } from '../shared/VulnPanelParts'
import { OperatingFilter } from '../shared/OperatingFilter'
import { SLA_SKELETON_COLUMNS, SLA_TEXT } from './slaConfig'
import { useSlaReport } from './useSlaReport'
import { SlaByRepoTable, SlaBySeverityTable, SlaOverdueTable, SlaPolicyNote, SlaSummaryTiles } from './SlaSections'

// 対応状況（SLA）。使っている画面（タブの中の小タブ）。取得は、表示されたときに始まる。
// 取得は useSlaReport、文言は slaConfig、表は SlaSections。ここは、並べるだけ
export function SlaPanel({ authToken }: { authToken?: string }) {
  const { operating, setOperating, loading, report, reload } = useSlaReport(authToken)

  return (
    <PanelFrame label={SLA_TEXT.label} icon={Timer} onReload={reload} reloading={loading}>
      <p className="text-xs text-slate-500">{SLA_TEXT.description}</p>

      <LastFetched crawlerType={SCREEN_FETCH_SOURCE.sla} />

      <div className="flex flex-wrap items-center gap-3">
        <OperatingFilter value={operating} onChange={setOperating} />
      </div>

      {loading ? (
        <TableLoadingSkeleton columnWidths={SLA_SKELETON_COLUMNS} />
      ) : report === null ? (
        <EmptyState icon={<Timer size={24} />} message={SLA_TEXT.loadFailed} />
      ) : (
        <>
          <SlaSummaryTiles report={report} />
          <SlaPolicyNote report={report} />
          <SlaOverdueTable report={report} />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <SlaBySeverityTable report={report} />
            <SlaByRepoTable report={report} />
          </div>
        </>
      )}
    </PanelFrame>
  )
}
