"""使っている言語・実行環境の版の状態を判定する（RUNTIME）。

「使っている版（系列）」と「リリース情報」を突き合わせ、対応が必要かを返す。DB にも HTTP にも
触れない純粋な判定のため、日付を引数で受け取る（テストしやすくするため）。

状態（`RuntimeState`）:

- `eol`: サポートが終了している（セキュリティ修正が提供されない）
- `eol_soon`: サポート終了が近い（`EOL_SOON_DAYS` 日以内）
- `update_available`: 推奨の系列（サポート中で公開から経った最新）が、使っている系列より新しい
- `latest`: 最新の系列を使っている
- `reference`: 下限の指定（`engines` など）で、実際に動いている版が分からない。参考表示のみ
- `unknown`: リリース情報に無い系列（取得前・未対応）
"""
from dataclasses import dataclass
from datetime import date
from typing import Literal

from app.runtimes.detector import NODEJS
from app.runtimes.models import RuntimeRelease

RuntimeState = Literal["eol", "eol_soon", "update_available", "latest", "reference", "unknown"]

# サポート終了まで、この日数以内になったら「期限間近」とする
EOL_SOON_DAYS = 180

# 公開からこの日数が経った系列を、推奨の対象にする。公開直後の系列は、ライブラリの対応が
# 追いつかないことが多く、使っているリポジトリが全て「更新あり」になって警告が多くなるため
RECOMMEND_MIN_AGE_DAYS = 180

# 対応が必要な状態（ダッシュボードの「更新が必要なものだけ」・通知の対象）
NEEDS_ACTION_STATES: frozenset[str] = frozenset({"eol", "eol_soon", "update_available"})


@dataclass(frozen=True)
class RuntimeStatus:
    """使っている版1件の判定結果。"""

    state: RuntimeState
    latest_version: str | None  # 使っている系列の最新版（パッチの更新の目安）
    recommended_cycle: str | None  # 推奨の系列（サポート中で公開から経った最新。Node は LTS のみ）
    recommended_version: str | None  # 推奨の系列の最新版
    eol_date: date | None
    days_to_eol: int | None


def cycle_key(cycle: str) -> tuple[int, ...]:
    """系列を、大小比較できる数のタプルにする（`3.9` < `3.13`、`22` < `24`）。"""
    try:
        return tuple(int(part) for part in cycle.split("."))
    except ValueError:
        return (0,)


def recommended_release(
    runtime: str, releases: list[RuntimeRelease], today: date,
) -> RuntimeRelease | None:
    """推奨の系列を返す。サポート中で、公開から十分に経った系列のうち最新のもの。

    Node.js は LTS のみ。公開から十分に経った系列が無いときは、サポート中の最新を返す。
    """
    candidates = [
        r for r in releases
        if r.runtime == runtime and not r.is_eol and (r.is_lts or runtime != NODEJS)
    ]
    settled = [
        r for r in candidates
        if r.release_date is None or (today - r.release_date).days >= RECOMMEND_MIN_AGE_DAYS
    ]
    return max(settled or candidates, key=lambda r: cycle_key(r.cycle), default=None)


def evaluate(
    runtime: str, cycle: str, *, pinned: bool, releases: list[RuntimeRelease], today: date,
) -> RuntimeStatus:
    """使っている版（系列）の状態を判定する。"""
    own = [r for r in releases if r.runtime == runtime]
    used = next((r for r in own if r.cycle == cycle), None)
    recommended = recommended_release(runtime, own, today)

    eol_date = used.eol_date if used else None
    days_to_eol = (eol_date - today).days if eol_date else None

    state: RuntimeState
    if not pinned:
        state = "reference"
    elif used is None:
        state = "unknown"
    elif used.is_eol or (days_to_eol is not None and days_to_eol < 0):
        state = "eol"
    elif days_to_eol is not None and days_to_eol <= EOL_SOON_DAYS:
        state = "eol_soon"
    elif recommended is not None and cycle_key(recommended.cycle) > cycle_key(cycle):
        state = "update_available"
    else:
        state = "latest"

    return RuntimeStatus(
        state=state,
        latest_version=used.latest_version if used else None,
        recommended_cycle=recommended.cycle if recommended else None,
        recommended_version=recommended.latest_version if recommended else None,
        eol_date=eol_date,
        days_to_eol=days_to_eol,
    )
