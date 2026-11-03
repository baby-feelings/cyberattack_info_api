"""Dockerfile の診断。
"""
import re

from app.codescan.iac_rules.common import (
    _SECRET_NAME,
    ERROR,
    WARNING,
    IacIssue,
    _is_literal_value,
    _snippet,
)

_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?",
                   re.IGNORECASE)
_USER = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.IGNORECASE)
_COPY_ADD = re.compile(r"^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*(?P<args>.+)$", re.IGNORECASE)
_ENV_ARG = re.compile(r"^\s*(?:ENV|ARG)\s+(?P<body>.+)$", re.IGNORECASE)
_PIPE_TO_SHELL = re.compile(r"(curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", re.IGNORECASE)
# イメージに入れてはいけないファイル（シークレット・鍵・認証情報）
_SECRET_FILE = re.compile(
    r"(?:^|[\s/])(?:\.env(?:\.\w+)?|id_rsa|id_ed25519|\.npmrc|\.pypirc|\.netrc|credentials\.json|"
    r"service-?account[\w.-]*\.json|[\w.-]+\.(?:pem|key|p12|pfx))(?:\s|$)",
    re.IGNORECASE,
)


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """`\\` 継続行を1行にまとめた (開始行番号, 内容) の一覧（コメント・空行は除く）。"""
    result: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        result.append((start, buffer + stripped))
        buffer = ""
    if buffer:
        result.append((start, buffer))
    return result


def _env_pairs(body: str) -> list[tuple[str, str]]:
    """`ENV KEY=value K2=v2` または `ENV KEY value`・`ARG KEY=value` の (キー, 値) の一覧。"""
    if "=" in body.split()[0]:
        pairs = []
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S*)", body):
            key, _, value = token.partition("=")
            pairs.append((key, value))
        return pairs
    parts = body.split(None, 1)
    return [(parts[0], parts[1] if len(parts) > 1 else "")]


def check_dockerfile(text: str) -> list[IacIssue]:  # noqa: C901 - ルールを1か所で一覧できるようにする
    """Dockerfile の代表的な不備（root 実行・latest タグ・シークレットの混入）を検知する。"""
    issues: list[IacIssue] = []
    stage_aliases: set[str] = set()
    last_from_line = 0
    has_user_in_last_stage = False
    last_user_is_root = False

    for number, line in _logical_lines(text):
        from_match = _FROM.match(line)
        if from_match:
            image = from_match.group("image")
            last_from_line = number
            has_user_in_last_stage, last_user_is_root = False, False
            tag_part = image.split("@")[0]
            tagless = ":" not in tag_part.rsplit("/", 1)[-1]
            if (
                image.lower() != "scratch" and image not in stage_aliases
                and "@sha256:" not in image
                and "$" not in image and (tagless or tag_part.endswith(":latest"))
            ):
                issues.append(IacIssue(
                    number, "dockerfile-latest-tag", WARNING,
                    f"ベースイメージ `{image}` が、タグなし・`latest` です。"
                    "ビルドのたびに中身が変わり、"
                    "再現できず、悪意ある更新も取り込みます。"
                    " 対策: 版（例: `python:3.13-slim`）、できればダイジェスト"
                    "（`@sha256:...`）で固定する。",
                    _snippet(line), "CWE-1104",
                ))
            if from_match.group("alias"):
                stage_aliases.add(from_match.group("alias"))
            continue

        user_match = _USER.match(line)
        if user_match:
            has_user_in_last_stage = True
            last_user_is_root = user_match.group("user").split(":")[0].lower() in {"root", "0"}
            continue

        copy_match = _COPY_ADD.match(line)
        if copy_match and _SECRET_FILE.search(" " + copy_match.group("args")):
            issues.append(IacIssue(
                number, "dockerfile-secret-copy", ERROR,
                "シークレット・鍵・認証情報のファイルを、イメージに入れています。イメージを取得できる人に、"
                "すべて読まれます（レイヤーに残るため、あとで消しても取り出せます）。"
                " 対策: イメージに入れず、実行時の環境変数・シークレット管理で渡す。"
                "`.dockerignore` にも追加する。",
                _snippet(line), "CWE-540",
            ))

        env_match = _ENV_ARG.match(line)
        if env_match:
            for key, value in _env_pairs(env_match.group("body")):
                if _SECRET_NAME.search(key) and _is_literal_value(value):
                    issues.append(IacIssue(
                        number, "dockerfile-secret-env", ERROR,
                        f"`{key}` に、認証情報らしい値を直書きしています（値は伏せています）。"
                        "イメージの履歴から読み取れます。"
                        " 対策: 直書きをやめ、実行時の環境変数・シークレット管理で渡す"
                        "（`ARG` も、ビルド履歴に残る）。",
                        f"{line.split()[0].upper()} {key}=***", "CWE-798",
                    ))

        if _PIPE_TO_SHELL.search(line):
            issues.append(IacIssue(
                number, "dockerfile-pipe-to-shell", WARNING,
                "ダウンロードしたスクリプトを、検証せずにシェルで実行しています（供給網の攻撃の入口）。"
                " 対策: ダウンロードして、チェックサム（`sha256sum -c`）で検証してから実行する。",
                _snippet(line), "CWE-494",
            ))

    # 最後のステージが root のまま動く（USER が無い・root を指定）
    if last_from_line and (not has_user_in_last_stage or last_user_is_root):
        issues.append(IacIssue(
            last_from_line, "dockerfile-root-user", WARNING,
            "コンテナが root で動きます。侵入された場合の被害が大きくなります。"
            " 対策: 一般ユーザーを作り、`USER` で切り替える"
            "（例: `RUN useradd -m app` → `USER app`）。",
            "(最後のステージに、root 以外の USER の指定がありません)", "CWE-250",
        ))
    return issues
