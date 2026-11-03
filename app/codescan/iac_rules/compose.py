"""docker-compose の診断。
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
