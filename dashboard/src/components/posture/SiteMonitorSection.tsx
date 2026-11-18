import { SCREEN_FETCH_SOURCE } from '../freshness/freshnessConfig'
import { safeHttpUrl } from '../shared/safeUrl'
import type { SiteCheck } from './model/SiteCheck'
import { POSTURE_TEXT, SITE_SEVERITY_VIEW } from './postureConfig'
import { PostureSection } from './PostureSection'
import type { Source } from './usePostureData'

// 公開サイトの外形監視（TLS 証明書の期限・ヘッダー・露出ファイルなど）の結果。判定は、API の指摘に従う。
export function SiteMonitorSection({ source, onRetry }: { source: Source<SiteCheck[]>; onRetry: () => void }) {
  return (
    <PostureSection
      title={POSTURE_TEXT.sites.title}
      crawlerType={SCREEN_FETCH_SOURCE.postureSites}
      source={source}
      onRetry={onRetry}
    >
      {(sites) => sites.length === 0 ? (
        <p className="text-sm text-slate-400">{POSTURE_TEXT.sites.empty}</p>
      ) : (
        <div className="relative overflow-x-auto">
          <table aria-label={POSTURE_TEXT.sites.title} className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-400">
                <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.sites.columns.url}</th>
                <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.sites.columns.tls}</th>
                <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.sites.columns.findings}</th>
              </tr>
            </thead>
            <tbody>
              {sites.map((site) => {
                const href = safeHttpUrl(site.url)
                return (
                  <tr key={site.url} className="border-t border-slate-800 align-top">
                    <td className="px-3 py-2 text-slate-200 whitespace-nowrap">
                      {href ? (
                        <a href={href} target="_blank" rel="noopener noreferrer" className="text-sky-400 hover:underline">{site.url}</a>
                      ) : site.url}
                    </td>
                    <td className="px-3 py-2 text-slate-300 tabular-nums">
                      {site.tlsDaysLeft === null ? '—' : `${site.tlsDaysLeft}${POSTURE_TEXT.sites.tlsUnit}`}
                    </td>
                    <td className="px-3 py-2">
                      {site.findings.length === 0 ? (
                        <span className="text-slate-400">{POSTURE_TEXT.sites.noFindings}</span>
                      ) : (
                        <ul className="flex flex-col gap-0.5">
                          {site.findings.map((finding, index) => {
                            const view = SITE_SEVERITY_VIEW[finding.severity] ?? SITE_SEVERITY_VIEW.INFO
                            return (
                              <li key={`${finding.rule}-${index}`} className={`flex gap-1.5 ${view.cls}`}>
                                <span aria-hidden="true">{view.glyph}</span>
                                <span>{finding.message}</span>
                              </li>
                            )
                          })}
                        </ul>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </PostureSection>
  )
}
