"""設定の点検項目の判定とスコア化（純粋なロジック。API への問い合わせは `collector`）。

各項目の状態:
- `ok`: 設定されている
- `ng`: 設定されていない・不備がある（改善すべき。`fix` に、直し方を示す）
- `unavailable`: 取得できない（権限不足・機能が使えない）。スコアの分母に含めない
- `not_enforceable`: 設定できない（非公開の無料リポジトリのブランチ保護）。
  不備とは区別し、分母に含めない
"""
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

OK = "ok"
NG = "ng"
UNAVAILABLE = "unavailable"
NOT_ENFORCEABLE = "not_enforceable"

# スコアに数える状態（これ以外は、分母にも含めない）
_SCORED = (OK, NG)

# 取得できない項目の説明
_NO_ACCESS = "取得できません（権限不足、またはプランの対象外）"


@dataclass(frozen=True)
class Check:
    """点検項目1件の判定。"""

    key: str
    label: str
    status: str
    weight: int
    detail: str
    fix: str = ""


def _flag(analysis: dict[str, Any] | None, name: str) -> bool | None:
    """`security_and_analysis` の機能の有効・無効（取得できなければ None）。"""
    if analysis is None:
        return None
    feature = analysis.get(name)
    if not isinstance(feature, dict):
        return None
    return feature.get("status") == "enabled"


def _toggle(key: str, label: str, enabled: bool | None, weight: int, fix: str) -> Check:
    if enabled is None:
        return Check(key, label, UNAVAILABLE, weight, _NO_ACCESS)
    if enabled:
        return Check(key, label, OK, weight, "有効です")
    return Check(key, label, NG, weight, "無効です", fix)


def _branch_protection(protection: Any) -> Check:
    """既定ブランチの保護。

    `protection`: 設定の辞書・False（未保護）・None（取得不可）・"not_enforceable"（設定できない）。
    """
    key, label = "branch_protection", "既定ブランチの保護"
    if protection == "not_enforceable":
        return Check(
            key, label, NOT_ENFORCEABLE, 3,
            "非公開の無料リポジトリのため、ブランチ保護を設定できません（強制できません）",
        )
    if protection is None:
        return Check(key, label, UNAVAILABLE, 3, "取得できません（権限不足）")
    if protection is False:
        return Check(
            key, label, NG, 3, "保護されていません",
            "Settings → Branches で、必須レビュー・必須チェックのルールを追加する",
        )
    weak = []
    if not protection.get("required_pull_request_reviews"):
        weak.append("必須レビュー")
    if not protection.get("required_status_checks"):
        weak.append("必須チェック")
    if weak:
        return Check(
            key, label, NG, 3, f"保護はありますが、{'・'.join(weak)}がありません",
            "ルールに、必須レビュー・必須チェックを追加する",
        )
    return Check(key, label, OK, 3, "保護されています")


def _forking(repo: dict[str, Any]) -> Check | None:
    """非公開リポジトリでフォークが許可されていると、コードが外へ持ち出されうる（公開は対象外）。"""
    if not repo.get("private"):
        return None
    if repo.get("allow_forking"):
        return Check(
            "forking", "フォークの許可", NG, 1, "非公開ですが、フォークが許可されています",
            "Settings → General → Allow forking を無効にする",
        )
    return Check("forking", "フォークの許可", OK, 1, "フォークは許可されていません")


def _deploy_keys(keys: list[dict[str, Any]] | None) -> Check:
    if keys is None:
        return Check("deploy_keys", "デプロイキー", UNAVAILABLE, 2, "取得できません（権限不足）")
    writable = [str(k.get("title")) for k in keys if not k.get("read_only", True)]
    if writable:
        return Check(
            "deploy_keys", "デプロイキー", NG, 2,
            f"書き込み権限つきのキーがあります: {', '.join(writable)}",
            "不要なキーは削除し、必要なら読み取り専用にする",
        )
    return Check("deploy_keys", "デプロイキー", OK, 2, f"{len(keys)}件（すべて読み取り専用）")


def sanitize_url(url: str) -> str:
    """URL から、認証情報（`user:pass@`）・クエリ・フラグメントを除く（表示・保存・通知用）。

    Webhook の送信先の URL には、トークンがクエリや認証情報として含まれることがある。
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def hook_url(hook: dict[str, Any]) -> str:
    """Webhook の送信先。GitHub の応答では `config.url`（互換のため、直下の `url` も見る）。"""
    return str((hook.get("config") or {}).get("url") or hook.get("url") or "")


def _is_insecure_hook(hook: dict[str, Any]) -> bool:
    """暗号化されていない送信先（http）、または SSL 検証を無効にした Webhook か。"""
    config = hook.get("config") or {}
    insecure_ssl = config.get("insecure_ssl", hook.get("insecure_ssl"))
    return hook_url(hook).lower().startswith("http://") or str(insecure_ssl) == "1"


def _webhooks(hooks: list[dict[str, Any]] | None) -> Check:
    if hooks is None:
        return Check("webhooks", "Webhook", UNAVAILABLE, 2, "取得できません（権限不足）")
    insecure = [sanitize_url(hook_url(h)) for h in hooks if _is_insecure_hook(h)]
    if insecure:
        return Check(
            "webhooks", "Webhook", NG, 2,
            f"暗号化されていない送信先があります: {', '.join(insecure)}",
            "https の送信先にし、SSL 検証を有効にする",
        )
    return Check("webhooks", "Webhook", OK, 2, f"{len(hooks)}件")


def evaluate(raw: dict[str, Any]) -> list[Check]:
    """収集した設定（`collector.collect` の結果）から、各項目を判定する。"""
    repo = raw.get("repo")
    analysis = repo.get("security_and_analysis") if repo is not None else None
    checks = [
        _toggle(
            "secret_scanning", "Secret scanning", _flag(analysis, "secret_scanning"), 3,
            "Settings → Code security → Secret scanning を有効にする",
        ),
        _toggle(
            "push_protection", "Push protection",
            _flag(analysis, "secret_scanning_push_protection"), 2,
            "Settings → Code security → Push protection を有効にする"
            "（push 時にシークレットを止める）",
        ),
        _toggle(
            "dependabot_alerts", "Dependabot alerts", raw.get("vulnerability_alerts"), 3,
            "Settings → Code security → Dependabot alerts を有効にする",
        ),
        _toggle(
            "dependabot_updates", "Dependabot security updates",
            _flag(analysis, "dependabot_security_updates"), 2,
            "Settings → Code security → Dependabot security updates を有効にする",
        ),
        _branch_protection(raw.get("branch_protection")),
    ]
    forking = _forking(repo) if repo is not None else None
    if forking is not None:
        checks.append(forking)
    checks += [_deploy_keys(raw.get("keys")), _webhooks(raw.get("hooks"))]
    return checks


def score(checks: list[Check]) -> int | None:
    """点検できた項目（ok・ng）の、重み付きの達成率（0〜100）。点検できた項目が無ければ None。"""
    scored = [c for c in checks if c.status in _SCORED]
    total = sum(c.weight for c in scored)
    if not total:
        return None
    return round(100 * sum(c.weight for c in scored if c.status == OK) / total)


def to_dicts(checks: list[Check]) -> list[dict[str, Any]]:
    return [asdict(c) for c in checks]


def merge_snapshots(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    """今回の取得で取れなかった種類（None）は、前回の内容を残す。

    None で上書きすると、次に取得できたとき、「前回が無い」ことになり、その間の変化
    （追加された共同編集者など）を見逃してしまう。
    """
    old = old or {}
    return {kind: (value if value is not None else old.get(kind)) for kind, value in new.items()}


def diff_snapshot(old: dict[str, Any] | None, new: dict[str, Any]) -> list[dict[str, str]]:
    """デプロイキー・Webhook・共同編集者の、前回からの変化（追加・削除）。

    前回が無い（初回）ときは、変化として扱わない（全件が「追加」になり、通知が溢れるため）。
    取得できなかった種類（None）は、比べない。
    """
    if not old:
        return []
    changes: list[dict[str, str]] = []
    for kind in ("keys", "hooks", "collaborators"):
        before, after = old.get(kind), new.get(kind)
        if before is None or after is None:
            continue
        for name in sorted(set(after) - set(before)):
            changes.append({"kind": kind, "change": "added", "name": name})
        for name in sorted(set(before) - set(after)):
            changes.append({"kind": kind, "change": "removed", "name": name})
    return changes
