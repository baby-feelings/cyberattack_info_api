"""CVSS 3.1 基本値（Base Score）計算ユーティリティ。

NVD（National Vulnerability Database）が公開している CVSS v3.1 の正式な計算式
（https://www.first.org/cvss/v3.1/specification-document セクション7）をそのまま
実装する。KEV（`app.kev.models`）等、既存ドメインの `cvss_score`/`cvss_vector`
フィールドと同じ「score: float」「vector: 標準ベクター文字列」という形式を
前提にしており、CODESCAN（`app.codescan.cvss_mapping`）から利用される。

本モジュール自体はベクター文字列からスコアを機械的に算出するだけで、CVE ごとの
ベクター判断（AV/AC/PR/UI/S/C/I/A の割り当て）は行わない。ベストエフォートの
ベクター推定ロジックは `app.codescan.cvss_mapping` を参照。
"""
import math
import re

# ベクター文字列の各メトリクスの重み（CVSS 3.1 仕様書 Table 15-19 準拠）
_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

# PR（Privileges Required）は Scope の値によって重みが変わる（仕様書 Table 17）
_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H のような標準形式を解析する
_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:(?P<AV>[NALP])/"
    r"AC:(?P<AC>[LH])/"
    r"PR:(?P<PR>[NLH])/"
    r"UI:(?P<UI>[NR])/"
    r"S:(?P<S>[UC])/"
    r"C:(?P<C>[NLH])/"
    r"I:(?P<I>[NLH])/"
    r"A:(?P<A>[NLH])$"
)


def _roundup(value: float) -> float:
    """CVSS 仕様書が定義する Roundup 関数（小数第1位への切り上げ）。

    Python 標準の round() は四捨五入・偶数丸めのため使えない。浮動小数点誤差を
    避けるため、仕様書のリファレンス実装と同様に一度 100000 倍した整数で判定する。
    """
    int_value = int(round(value * 100000))
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (math.floor(int_value / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """CVSS 3.1 ベクター文字列を解析し、各メトリクスの1文字コードの辞書を返す。

    Raises:
        ValueError: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` の標準形式に
            一致しない場合
    """
    match = _VECTOR_RE.match(vector.strip())
    if match is None:
        raise ValueError(f"Invalid CVSS 3.1 vector string: {vector!r}")
    return match.groupdict()


def calculate_base_score(vector: str) -> float:
    """CVSS 3.1 ベクター文字列から基本値（Base Score, 0.0〜10.0）を算出する。

    NVD の公式計算式（Impact Sub-Score・Exploitability Sub-Score・Scope による
    分岐）をそのまま実装している。Environmental/Temporal メトリクスは対象外。

    Args:
        vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` 形式のベクター文字列

    Returns:
        基本値（小数第1位、0.0〜10.0）

    Raises:
        ValueError: ベクター文字列の形式が不正な場合
    """
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    av = _AV_WEIGHTS[m["AV"]]
    ac = _AC_WEIGHTS[m["AC"]]
    pr_weights = _PR_WEIGHTS_CHANGED if scope_changed else _PR_WEIGHTS_UNCHANGED
    pr = pr_weights[m["PR"]]
    ui = _UI_WEIGHTS[m["UI"]]
    c = _CIA_WEIGHTS[m["C"]]
    i = _CIA_WEIGHTS[m["I"]]
    a = _CIA_WEIGHTS[m["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))
