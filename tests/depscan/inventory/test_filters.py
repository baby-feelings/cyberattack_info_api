"""app.depscan.inventory.filters（依存パッケージの絞り込み条件）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.depscan.inventory.filters import DependencyFilter  # noqa: E402
from app.depscan.models import RepoDependency  # noqa: E402


def _add(db, repo, name, version="1.0.0", ecosystem="npm"):
    db.add(RepoDependency(
        repo_full_name=repo, ecosystem=ecosystem, package_name=name, version=version,
        manifest_path="package-lock.json",
    ))


def _apply(db, flt):
    return sorted(
        (r.repo_full_name, r.package_name) for r in flt.apply(db.query(RepoDependency)).all()
    )


class TestDependencyFilter:
    def test_default_filter_does_not_restrict(self, db_session):
        _add(db_session, "alice/web", "undici")
        _add(db_session, "bob/app", "axios")
        db_session.commit()
        assert len(_apply(db_session, DependencyFilter())) == 2

    def test_is_an_immutable_value_object(self):
        flt = DependencyFilter(package="undici")
        same = DependencyFilter(package="undici")
        assert flt == same
        try:
            flt.package = "other"  # type: ignore[misc]
        except AttributeError:
            pass
        else:
            raise AssertionError("frozen dataclass should reject assignment")

    def test_for_owner_returns_a_new_restricted_filter(self, db_session):
        _add(db_session, "alice/web", "undici")
        _add(db_session, "bob/app", "undici")
        db_session.commit()
        base = DependencyFilter(package="undici")

        restricted = base.for_owner("alice")

        assert restricted is not base and base.owner is None  # 元の条件は変わらない
        assert _apply(db_session, restricted) == [("alice/web", "undici")]
        assert len(_apply(db_session, base)) == 2

    def test_for_owner_none_keeps_it_unrestricted(self, db_session):
        _add(db_session, "alice/web", "undici")
        db_session.commit()
        assert _apply(db_session, DependencyFilter().for_owner(None)) == [("alice/web", "undici")]

    def test_conditions_combine(self, db_session):
        _add(db_session, "alice/web", "undici", "8.11.2")
        _add(db_session, "alice/web", "undici", "8.12.3")
        _add(db_session, "alice/api", "undici", "8.11.2")
        _add(db_session, "alice/api", "fastapi", "0.141.0", ecosystem="PyPI")
        db_session.commit()

        flt = DependencyFilter(package="UNDI", version="8.11.2", ecosystem="npm", repo="alice/api")

        assert _apply(db_session, flt) == [("alice/api", "undici")]
