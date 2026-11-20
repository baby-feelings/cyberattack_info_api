"""app.finding_exceptions.filters（例外を含めるかの共通の絞り込み）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.codescan.filters import CodescanListFilter  # noqa: E402
from app.depscan.filters import DepscanListFilter  # noqa: E402
from app.finding_exceptions.filters import ExceptableFindingFilter  # noqa: E402
from app.finding_exceptions.models import KIND_CODE, KIND_DEPENDENCY  # noqa: E402


def test_DEPSCANとCODESCANは_例外の絞り込みを共通の基底で持つ():
    """どちらも ExceptableFindingFilter を継承し、対象の種別（kind）だけが違う。"""
    assert issubclass(DepscanListFilter, ExceptableFindingFilter)
    assert issubclass(CodescanListFilter, ExceptableFindingFilter)
    assert DepscanListFilter.kind == KIND_DEPENDENCY
    assert CodescanListFilter.kind == KIND_CODE


def test_include_excepted_の既定は_含める():
    """未指定なら例外の検知も含める（従来の挙動）。"""
    f = DepscanListFilter(
        repo=None, owner=None, ecosystem=None, severity=None, resolved=None,
        operating="all", include_excepted=True,
    )
    assert f.include_excepted is True
