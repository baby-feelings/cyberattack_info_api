"""Semgrep の検知結果から CVSS 3.1 ベクターをベストエフォートで推定する。

【設計上の注意（必ず読むこと）】
真の CVSS 基本値は、既知の脆弱性1件ごとに人間が実際の攻撃条件を分析して
AV/AC/PR/UI/S/C/I/A の8メトリクスを個別に判断するものであり、静的解析ツールの
検知結果（ルールID・重要度・CWE）だけから機械的に正確な CVSS を算出することは
原理的に不可能である。本モジュールは「対応の優先順位付けの参考値」として
ベストエフォードの近似値を提供するに過ぎず、精度を保証しない
（Issue #203 の要件どおり、この旨をコード・ドキュメントに明記している）。

推定方針:
1. ネットワークから直接攻撃可能かどうかを静的解析結果だけで機械的に判定するのは
   困難なため、保守的に AV:N（Network）をデフォルトとする。CWE カテゴリから
   明らかにローカル限定と判断できるもの（例: ハードコード認証情報の露出は
   まずソースコードへのアクセスが前提）のみ AV:L に調整する。
2. 既知の代表的な CWE カテゴリ（認証情報のハードコード・SQLi・コマンドインジェクション・
   XSS・安全でない暗号・パストラバーサル等）には、脆弱性クラスとして妥当性の高い
   ベクターを個別にハードコードしたマッピング辞書を用意する。
3. 未知の CWE・CWE 情報なしの場合は、Semgrep の severity（ERROR/WARNING/INFO）に
   基づく粗いフォールバックベクターを使う（ERROR ほど影響大 = C:H/I:H 寄り、
   INFO ほど影響小 = C:L/N 寄り）。
"""
import re

# Semgrep の extra.metadata.cwe は "CWE-798: Use of Hard-coded Credentials" のような
# 文字列で来る。番号部分だけを取り出して照合する
_CWE_NUM_RE = re.compile(r"CWE-(\d+)")

# 既知 CWE カテゴリ → CVSS 3.1 ベクター（ベストエフォート、妥当性の高い代表値）。
# 各エントリはそのCWEクラスの典型的な悪用シナリオを想定したベクター。
_CWE_VECTOR_MAP: dict[int, str] = {
    # CWE-798: ハードコードされた認証情報
    # ソースコードの閲覧・リポジトリへのアクセスが前提となるため AV:L とし、
    # 認証情報自体が漏洩すればC/I/Aすべてに影響しうるためH寄りにする
    798: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    # CWE-89: SQLインジェクション（リモートから攻撃可能、機密性・完全性への影響大）
    89: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    # CWE-78: OSコマンドインジェクション（リモートコード実行相当、可用性にも影響）
    78: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    # CWE-79: クロスサイトスクリプティング（被害者の操作が必要、影響はセッション窃取等）
    79: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    # CWE-327 / CWE-326: 安全でない暗号アルゴリズム・不十分な鍵強度
    # （即座の侵害ではなく将来的な復号リスクのため中程度の影響）
    327: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    326: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    # CWE-22: パストラバーサル（リモートから任意ファイル読み取り相当）
    22: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# severity ベースのフォールバックベクター（既知CWEに該当しない場合）。
# ERROR=影響大寄り、WARNING=中程度、INFO=低程度という粗い区分。
_SEVERITY_FALLBACK_VECTOR: dict[str, str] = {
    "ERROR": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "WARNING": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "INFO": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}

# デフォルト（severityが未知の値だった場合の最終フォールバック）
_DEFAULT_VECTOR = _SEVERITY_FALLBACK_VECTOR["WARNING"]


def _extract_cwe_numbers(cwe_list: list[str] | None) -> list[int]:
    """`["CWE-798: Use of Hard-coded Credentials", ...]` のような文字列群から
    番号部分（798 等）のみを抽出する。数値化できないものは無視する。
    """
    if not cwe_list:
        return []
    numbers = []
    for cwe in cwe_list:
        match = _CWE_NUM_RE.search(cwe)
        if match:
            numbers.append(int(match.group(1)))
    return numbers


def estimate_cvss_vector(severity: str, cwe_list: list[str] | None) -> str:
    """Semgrep の検知結果（severity・CWE）から CVSS 3.1 ベクターをベストエフォートで推定する。

    既知の CWE カテゴリに一致すれば妥当性の高い個別ベクターを、一致しなければ
    severity に基づく粗いフォールバックベクターを返す。精度は保証しない
    （本モジュール docstring 参照）。

    Args:
        severity: Semgrep の重要度（"ERROR" / "WARNING" / "INFO"）
        cwe_list: `extra.metadata.cwe`（例: `["CWE-798: Use of Hard-coded Credentials"]`）。
            無い場合は None または空リスト

    Returns:
        CVSS 3.1 ベクター文字列（`app.core.cvss.calculate_base_score` に渡せる形式）
    """
    for cwe_num in _extract_cwe_numbers(cwe_list):
        if cwe_num in _CWE_VECTOR_MAP:
            return _CWE_VECTOR_MAP[cwe_num]

    return _SEVERITY_FALLBACK_VECTOR.get(severity.upper(), _DEFAULT_VECTOR)
