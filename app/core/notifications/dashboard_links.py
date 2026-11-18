"""通知・Issue から、ダッシュボードの特定のタブ・小タブへ直接開くリンク。

URL は `<ダッシュボード>/?tab=<タブのキー>&sub=<小タブのキー>`。キーは、ダッシュボードの
`dashboard/src/components/layout/tabs.tsx` の `TabKey`・小タブの `key` と同じ値で、
パラメータ名は `dashboard/src/components/layout/deepLink.ts` の `DEEP_LINK_PARAM` と同じ。
タブを増減・改名したら、ここも合わせる。知らないキーが来ても、ダッシュボード側は無視して概要を開く。
"""
from dataclasses import dataclass
from urllib.parse import urlencode

from app.core.notifications.slack import DASHBOARD_URL

TAB_PARAM = "tab"
SUB_PARAM = "sub"


@dataclass(frozen=True)
class DashboardTarget:
    """ダッシュボードの開き先（タブと、あれば小タブ）。"""

    tab: str
    sub: str | None = None

    def url(self, base: str = DASHBOARD_URL) -> str:
        params = {TAB_PARAM: self.tab}
        if self.sub:
            params[SUB_PARAM] = self.sub
        return f"{base}?{urlencode(params)}"


# 依存ライブラリ
DEPS_SCAN = DashboardTarget("dependencies", "scan")
DEPS_SLA = DashboardTarget("dependencies", "sla")
DEPS_DEPENDABOT_OPS = DashboardTarget("dependencies", "depsops")
DEPS_RUNTIMES = DashboardTarget("dependencies", "runtimes")
DEPS_ALERTS = DashboardTarget("dependencies", "alerts")
# コードと設定
CODE_SCAN = DashboardTarget("code", "scan")
CODE_ALERTS = DashboardTarget("code", "alerts")
CODE_AUDIT = DashboardTarget("code", "audit")
# 運用
OPS_SITES = DashboardTarget("ops")
# 公開情報
PUBLIC_KEV = DashboardTarget("public", "kev")
PUBLIC_OSV = DashboardTarget("public", "osv")

# クローラーの種別ごとの、更新通知の開き先。ここに無い種別は、ダッシュボードのトップを開く
_CRAWLER_TARGETS: dict[str, DashboardTarget] = {
    "KEV": PUBLIC_KEV,
    "OSV": PUBLIC_OSV,
    "DEPSCAN": DEPS_SCAN,
    "DEPSOPS": DEPS_DEPENDABOT_OPS,
    "CODESCAN": CODE_SCAN,
    "RUNTIME": DEPS_RUNTIMES,
    "GHALERT": CODE_ALERTS,
    "REPOAUDIT": CODE_AUDIT,
    "EXTMON": OPS_SITES,
}


def crawler_link(crawler_type: str) -> str:
    """クローラーの種別に対応するタブへのリンク。対応が無ければ、ダッシュボードのトップ。"""
    target = _CRAWLER_TARGETS.get(crawler_type)
    return target.url() if target else DASHBOARD_URL
