"""一覧 API の絞り込み条件クラス（app.core.list_filters と各ドメインの filters.py）のテスト。

クラスのコンストラクタは FastAPI が `Query(...)` 既定値付きで呼ぶ想定のため、
テストではすべての引数を明示して直接生成する。
"""
import pytest
from fastapi import HTTPException

from app.codescan.filters import CodescanListFilter
from app.codescan.models import CodeFinding
from app.core.list_filters import RepoFindingFilter
from app.depscan.filters import DepscanListFilter
from app.depscan.models import DependencyFinding
from app.jvn.filters import JvnListFilter
from app.kev.filters import KevListFilter
from app.kev.models import Vulnerability
from app.main import app
from app.osv.filters import OsvListFilter
from app.osv.models import OsvVulnerability


def _sql(query) -> str:
    """クエリをリテラル値込みの SQL 文字列にする（条件が含まれるかの検証用）。"""
    return str(query.statement.compile(compile_kwargs={"literal_binds": True}))


def _osv(**kw):
    base = dict(days=30, ecosystem=None, severity=None, search=None, sort_by="modified",
                updated_since=None)
    return OsvListFilter(**{**base, **kw})


def _jvn(**kw):
    base = dict(days=30, severity=None, search=None, sort_by="modified", updated_since=None)
    return JvnListFilter(**{**base, **kw})


class TestFeedListFilter:
    def test_base_query_limits_to_recent_days_on_the_date_column(self, db_session):
        sql = _sql(_osv().base_query(db_session))
        assert "osv_vulnerabilities.modified >=" in sql
        sql_jvn = _sql(_jvn().base_query(db_session))
        assert "jvn_vulnerabilities.date_last_modified >=" in sql_jvn

    def test_osv_severity_is_uppercased_and_ecosystem_matches_exactly(self, db_session):
        flt = _osv(severity="high", ecosystem="PyPI")
        sql = _sql(flt.apply(db_session.query(OsvVulnerability)))
        assert "osv_vulnerabilities.severity = 'HIGH'" in sql
        assert "osv_vulnerabilities.ecosystem = 'PyPI'" in sql

    def test_jvn_severity_is_capitalized(self, db_session):
        flt = _jvn(severity="hIGH")
        sql = _sql(flt.apply(db_session.query(_jvn().model)))
        assert "jvn_vulnerabilities.severity = 'High'" in sql

    def test_search_matches_any_of_the_declared_columns(self, db_session):
        sql = _sql(_osv(search="log4j").apply(db_session.query(OsvVulnerability))).lower()
        for col in ("osv_id", "package_name", "summary"):
            assert f"osv_vulnerabilities.{col}" in sql
        assert " or " in sql and "%log4j%" in sql

    def test_updated_since_filters_on_updated_at(self, db_session):
        from datetime import datetime, timezone
        flt = _jvn(updated_since=datetime(2026, 1, 2, tzinfo=timezone.utc))
        sql = _sql(flt.apply(db_session.query(flt.model)))
        assert "jvn_vulnerabilities.updated_at >=" in sql

    def test_no_conditions_leaves_query_unfiltered(self, db_session):
        query = db_session.query(OsvVulnerability)
        assert _sql(_osv().apply(query)) == _sql(query)

    def test_order_cvss_puts_nulls_last_and_default_is_date_desc(self):
        assert "cvss_score DESC NULLS LAST" in str(_osv(sort_by="cvss").order())
        assert "osv_vulnerabilities.modified DESC" in str(_osv().order())
        assert "jvn_vulnerabilities.date_last_modified DESC" in str(_jvn().order())


class TestKevListFilter:
    def test_applies_every_condition(self, db_session):
        from datetime import datetime, timezone
        flt = KevListFilter(
            search="micro", vendor="Microsoft", product="Exchange", min_epss=0.5,
            updated_since=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        sql = _sql(flt.apply(db_session.query(Vulnerability)))
        assert "vulnerabilities.vendor_project = 'Microsoft'" in sql
        assert "%Exchange%" in sql and "%micro%" in sql
        assert "vulnerabilities.epss_score >= 0.5" in sql
        assert "vulnerabilities.updated_at >=" in sql

    def test_min_epss_zero_is_still_applied(self, db_session):
        """0.0 は falsy だが「指定あり」なのでフィルターされる（is not None 判定）。"""
        flt = KevListFilter(search=None, vendor=None, product=None, min_epss=0.0,
                            updated_since=None)
        assert "epss_score >= 0.0" in _sql(flt.apply(db_session.query(Vulnerability)))


class TestRepoFindingFilter:
    def _depscan(self, **kw):
        base = dict(repo=None, owner=None, ecosystem=None, severity=None, resolved=None)
        return DepscanListFilter(**{**base, **kw})

    def _codescan(self, **kw):
        base = dict(repo=None, owner=None, severity=None, resolved=None, min_cvss=None)
        return CodescanListFilter(**{**base, **kw})

    def test_repo_owner_severity_conditions(self, db_session):
        flt = self._depscan(repo="o/r", owner="o", severity="high", ecosystem="npm")
        sql = _sql(flt.apply(db_session.query(DependencyFinding)))
        assert "repo_full_name = 'o/r'" in sql
        assert "repo_full_name LIKE 'o/%'" in sql
        assert "severity = 'HIGH'" in sql
        assert "ecosystem = 'npm'" in sql

    def test_resolved_true_false_and_unspecified(self, db_session):
        query = db_session.query(CodeFinding)
        assert "resolved_at IS NOT NULL" in _sql(self._codescan(resolved=True).apply(query))
        assert "resolved_at IS NULL" in _sql(self._codescan(resolved=False).apply(query))
        assert "WHERE" not in _sql(self._codescan(resolved=None).apply(query))

    def test_codescan_min_cvss(self, db_session):
        sql = _sql(self._codescan(min_cvss=7.0).apply(db_session.query(CodeFinding)))
        assert "cvss_score >= 7.0" in sql

    def test_restrict_to_owner_overrides_owner(self):
        flt = self._depscan(owner="someone-else")
        flt.restrict_to_owner("me")
        assert flt.owner == "me"

    def test_restrict_to_owner_rejects_other_users_repo(self):
        flt = self._depscan(repo="other/repo")
        with pytest.raises(HTTPException) as exc:
            flt.restrict_to_owner("me")
        assert exc.value.status_code == 403

    def test_restrict_to_owner_allows_own_repo_and_noop_for_api_key(self):
        own = self._depscan(repo="me/app")
        own.restrict_to_owner("me")
        assert own.repo == "me/app"

        api_key = RepoFindingFilter(repo="x/y", owner="x", severity=None, resolved=None)
        api_key.restrict_to_owner(None)
        assert api_key.owner == "x"


class TestListEndpointsExposeSameQueryParameters:
    """リファクタリングで公開APIのクエリパラメータ（名前・制約）が変わらないことの回帰ガード。"""

    @staticmethod
    def _params(path: str) -> dict[str, dict]:
        op = app.openapi()["paths"][path]["get"]
        return {p["name"]: p for p in op["parameters"]}

    def test_kev(self):
        params = self._params("/api/vulnerabilities")
        assert set(params) == {
            "page", "per_page", "search", "vendor", "product", "min_epss", "updated_since",
        }
        assert params["per_page"]["schema"]["maximum"] == 500
        assert params["min_epss"]["schema"]["anyOf"][0]["maximum"] == 1.0

    def test_osv_and_jvn(self):
        osv = self._params("/api/osv")
        assert set(osv) == {
            "page", "per_page", "days", "ecosystem", "severity", "search", "sort_by",
            "updated_since",
        }
        assert osv["days"]["schema"]["maximum"] == 365
        assert osv["sort_by"]["schema"]["enum"] == ["modified", "cvss"]
        jvn = self._params("/api/jvn")
        assert set(jvn) == {
            "page", "per_page", "days", "severity", "search", "sort_by", "updated_since",
        }

    def test_depscan_and_codescan(self):
        depscan = self._params("/api/depscan")
        assert {"repo", "owner", "ecosystem", "severity", "resolved", "page", "per_page"} <= set(
            depscan,
        )
        codescan = self._params("/api/codescan")
        assert {"repo", "owner", "severity", "resolved", "min_cvss", "page", "per_page"} <= set(
            codescan,
        )
        assert codescan["min_cvss"]["schema"]["anyOf"][0]["maximum"] == 10
