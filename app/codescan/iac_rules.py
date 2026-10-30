"""インフラ設定（Firebase のルール・Dockerfile・docker-compose）の診断ルール（Issue #400）。

外部ツールを増やさず、設定ファイルの文字列を読んで判定する純粋な関数だけで構成する
（ファイルの探索・レコード化は `scanners.InfraScanner`）。Firebase のセキュリティルールは、
市販の IaC 診断ツールが対応していないため自前で判定する。誤検知を避けるため、「代表的な不備」
に絞る（Web の公開ポート等は対象外。ヘッダー等の外から見える設定は、外形監視の役割）。

【重要・セキュリティ】シークレットの値そのものは、検知結果（スニペット・メッセージ）に残さない
（診断が、認証情報を漏らす側になってしまうため。gitleaks と同じ方針）。
キー名だけを示し、値は伏せる。
"""
import re
from dataclasses import dataclass

# 重要度（CODESCAN の重要度と同じ語）
ERROR = "ERROR"
WARNING = "WARNING"
INFO = "INFO"


@dataclass(frozen=True)
class IacIssue:
    """診断で見つけた不備1件（1行に紐づく）。"""

    line: int               # 1始まり
    rule: str               # `iac:` を除いたルール名（例: firestore-open-write）
    severity: str
    message: str            # 何が問題か＋「対策:」（修正方法）
    snippet: str            # 該当行（シークレットの値は伏せる）
    cwe: str | None = None  # 例: CWE-250


# ---------------------------------------------------------------------------
# 共通
# ---------------------------------------------------------------------------

# 認証情報らしい名前（環境変数・ARG のキー名）
_SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)", re.IGNORECASE,
)
_MAX_SNIPPET = 200


def _snippet(line: str) -> str:
    return line.strip()[:_MAX_SNIPPET]


# 明らかなダミー値（診断用・サンプル）。認証情報の直書きとは扱わない（誤検知を減らす）
_PLACEHOLDER = re.compile(
    r"dummy|example|changeme|change-me|placeholder|your[-_]|xxx|<.*>", re.IGNORECASE,
)


def _is_literal_value(value: str) -> bool:
    """値が、直書きのリテラルか。

    空・変数の参照（`$VAR`・`${VAR}`）・未設定・明らかなダミー値は、直書きの認証情報ではない。
    """
    cleaned = value.strip().strip("\"'")
    return bool(cleaned) and not cleaned.startswith("$") and not _PLACEHOLDER.search(cleaned)


# ---------------------------------------------------------------------------
# Firebase: Firestore / Cloud Storage のセキュリティルール
# ---------------------------------------------------------------------------

# `allow read, write: if <条件>;`（条件は複数行にまたがりうる。`;` まで）
_ALLOW = re.compile(
    r"allow\s+(?P<ops>[a-z,\s]+?)\s*(?::\s*if\s+(?P<cond>[^;]*?))?\s*;", re.IGNORECASE | re.DOTALL,
)
_WRITE_OPS = {"write", "create", "update", "delete"}
_TIME_LIMITED = re.compile(r"request\.time\s*<\s*timestamp\.date\(", re.IGNORECASE)
_ANY_SIGNED_IN = re.compile(r"^request\.auth\s*!=\s*null$")


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def check_firebase_rules(text: str) -> list[IacIssue]:
    """`firestore.rules`・`storage.rules` の過剰な公開を検知する。"""
    issues: list[IacIssue] = []
    for match in _ALLOW.finditer(text):
        ops = {op.strip().lower() for op in match.group("ops").split(",") if op.strip()}
        cond = " ".join((match.group("cond") or "").split())
        line = _line_of(text, match.start())
        snippet = _snippet(" ".join(match.group(0).split()))
        writes = bool(ops & _WRITE_OPS)

        if cond.lower() == "true":
            if writes:
                issues.append(IacIssue(
                    line, "firebase-open-write", ERROR,
                    "認証なしで、誰でも書き込み・削除できます（`if true`）。"
                    " 対策: `request.auth != null` に加え、所有者の確認"
                    "（例: `request.auth.uid == userId`）を条件にする。",
                    snippet, "CWE-862",
                ))
            else:
                issues.append(IacIssue(
                    line, "firebase-open-read", WARNING,
                    "認証なしで、誰でも読み取れます（`if true`）。意図した公開か確認してください。"
                    " 対策: 公開が不要なら `request.auth != null` と所有者の確認を条件にする。",
                    snippet, "CWE-862",
                ))
        elif _TIME_LIMITED.search(cond):
            issues.append(IacIssue(
                line, "firebase-test-mode", ERROR if writes else WARNING,
                "期限つきの公開（テストモードのルール）です。期限まで、誰でも読み書きできます。"
                " 対策: 本番では、認証と所有者の確認を条件にしたルールに置き換える。",
                snippet, "CWE-862",
            ))
        elif writes and _ANY_SIGNED_IN.match(cond):
            issues.append(IacIssue(
                line, "firebase-any-user-write", WARNING,
                "ログインしていれば、誰でも（他人のデータにも）書き込めます。"
                " 対策: 所有者の確認（例: `request.auth.uid == resource.data.ownerId`）を加える。",
                snippet, "CWE-285",
            ))
    return issues


# Realtime Database のルール（JSON）: `".read": true` / `".write": true`
_RTDB_OPEN = re.compile(r'"\.(?P<kind>read|write)"\s*:\s*(?P<value>true|"true")', re.IGNORECASE)


def check_realtime_db_rules(text: str) -> list[IacIssue]:
    """`database.rules.json`（Realtime Database）の、認証なしの読み書きを検知する。"""
    issues: list[IacIssue] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        match = _RTDB_OPEN.search(raw)
        if not match:
            continue
        writes = match.group("kind").lower() == "write"
        issues.append(IacIssue(
            number, "firebase-open-write" if writes else "firebase-open-read",
            ERROR if writes else WARNING,
            f"認証なしで、誰でも{'書き込み' if writes else '読み取り'}できます"
            f"（`.{match.group('kind')}: true`）。"
            " 対策: `auth != null` に加え、所有者の確認（例: `auth.uid === $uid`）を条件にする。",
            _snippet(raw), "CWE-862",
        ))
    return issues


# ---------------------------------------------------------------------------
# firebase.json
# ---------------------------------------------------------------------------

_HOSTING_PUBLIC_ROOT = re.compile(r'"public"\s*:\s*"(?:\.|\./?|)"')


def check_firebase_json(text: str) -> list[IacIssue]:
    """`firebase.json` の、リポジトリ全体の公開（`"public": "."`）を検知する。"""
    issues: list[IacIssue] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if _HOSTING_PUBLIC_ROOT.search(raw):
            issues.append(IacIssue(
                number, "firebase-hosting-public-root", ERROR,
                "Hosting の公開ディレクトリがリポジトリのルートです。ソースコードや設定ファイル"
                "（`.env`・`firebase.json` 等）まで公開されるおそれがあります。"
                " 対策: ビルド成果物のディレクトリ（例: `build/web`・`dist`）だけを指定する。",
                _snippet(raw), "CWE-538",
            ))
    return issues


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------

# 外部に公開してはいけないポート（DB・キャッシュ・検索・Docker API・メッセージキュー）
_SENSITIVE_PORTS = {
    2375: "Docker API（認証なし）", 2376: "Docker API", 3306: "MySQL", 5432: "PostgreSQL",
    5672: "RabbitMQ", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_PORT_ITEM = re.compile(
    r"^\s*-\s*[\"']?(?:(?P<bind>\d{1,3}(?:\.\d{1,3}){3}):)?(?P<host>\d+):(?P<container>\d+)"
    r"(?:/\w+)?[\"']?\s*$",
)
_COMPOSE_KV = re.compile(r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<value>.*?)\s*$")
_COMPOSE_ENV_ITEM = re.compile(
    r"^\s*-\s*[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^\"']*)[\"']?\s*$",
)


def check_docker_compose(text: str) -> list[IacIssue]:  # noqa: C901 - ルールを1か所で一覧できるようにする
    """docker-compose の、特権・ホストの乗っ取り・DB の外部公開・認証情報の直書きを検知する。"""
    issues: list[IacIssue] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.strip().startswith("#"):
            continue
        lowered = raw.strip().lower()

        if re.match(r"^privileged\s*:\s*[\"']?true", lowered):
            issues.append(IacIssue(
                number, "compose-privileged", ERROR,
                "特権コンテナです。ホストのほぼ全権限を持ち、侵入されるとホストごと奪われます。"
                " 対策: `privileged` をやめ、必要な権限だけを `cap_add` で付ける。",
                _snippet(raw), "CWE-250",
            ))
        elif "/var/run/docker.sock" in raw:
            issues.append(IacIssue(
                number, "compose-docker-sock", ERROR,
                "Docker ソケットをコンテナに渡しています。"
                "コンテナから、ホストの全コンテナを操作できます（ホストの乗っ取りと同じ）。"
                " 対策: 渡さない。必要なら、権限を絞ったソケットのプロキシを使う。",
                _snippet(raw), "CWE-250",
            ))
        elif re.match(r"^network_mode\s*:\s*[\"']?host", lowered):
            issues.append(IacIssue(
                number, "compose-host-network", WARNING,
                "ホストのネットワークを共有しています。コンテナのポートが、そのままホストに公開されます。"
                " 対策: 既定のネットワークにし、必要なポートだけ `ports` で公開する。",
                _snippet(raw), "CWE-668",
            ))
        elif (
            re.match(r"^-\s*[\"']?(all|sys_admin)\b", lowered)
            and "cap" in _recent_key(text, number)
        ):
            issues.append(IacIssue(
                number, "compose-dangerous-capability", WARNING,
                "強力な権限（`ALL`・`SYS_ADMIN`）をコンテナに付けています。"
                " 対策: 必要な権限だけを付ける。",
                _snippet(raw), "CWE-250",
            ))

        port = _PORT_ITEM.match(raw)
        if port:
            # コンテナ側のポートで判定し、無ければ、ホスト側（別のポートに割り当てた場合）で判定する
            sensitive = _SENSITIVE_PORTS.get(int(port.group("container"))) or _SENSITIVE_PORTS.get(
                int(port.group("host")),
            )
            if sensitive and port.group("bind") not in _LOOPBACK:
                issues.append(IacIssue(
                    number, "compose-exposed-port", ERROR,
                    f"{sensitive} のポートを、外部（全インターフェース）に公開しています。"
                    "インターネットから直接アクセスされるおそれがあります。"
                    " 対策: `127.0.0.1:ポート:ポート` にするか、`ports` をやめて、"
                    "内部ネットワークだけで使う。",
                    _snippet(raw), "CWE-668",
                ))

        item = _COMPOSE_ENV_ITEM.match(raw)
        kv = _COMPOSE_KV.match(raw)
        if item:
            key, value = item.group("key"), item.group("value")
        elif kv and kv.group("value") and not kv.group("value").endswith(":"):
            key, value = kv.group("key"), kv.group("value")
        else:
            continue
        # `*_FILE`（秘密を置いたファイルのパス）や、`/run/secrets/` は、直書きではない
        if (
            _SECRET_NAME.search(key) and not key.upper().endswith("_FILE")
            and _is_literal_value(value) and not value.strip().startswith("/run/secrets/")
        ):
            issues.append(IacIssue(
                number, "compose-secret-env", WARNING,
                f"`{key}` に、認証情報らしい値を直書きしています（値は伏せています）。"
                " 対策: `.env`（リポジトリに入れない）・`secrets:`・変数の参照（`${VAR}`）で渡す。",
                f"{key}: ***", "CWE-798",
            ))
    return issues


def _recent_key(text: str, line_number: int) -> str:
    """指定行より前で、直近の `key:` 行（リスト項目の、親のキー）。"""
    for raw in reversed(text.splitlines()[: line_number - 1]):
        match = _COMPOSE_KV.match(raw)
        if match and not raw.strip().startswith("-"):
            return match.group("key").lower()
    return ""
