"""インフラ設定（Firebase のルール・Dockerfile・docker-compose）の診断ルール（Issue #400）。

外部ツールを増やさず、設定ファイルの文字列を読んで判定する純粋な関数だけで構成する
（ファイルの探索・レコード化は `scanners.InfraScanner`）。Firebase のセキュリティルールは、
市販の IaC 診断ツールが対応していないため自前で判定する。誤検知を避けるため、「代表的な不備」
に絞る（Web の公開ポート等は対象外。ヘッダー等の外から見える設定は、外形監視の役割）。

【重要・セキュリティ】シークレットの値そのものは、検知結果（スニペット・メッセージ）に残さない
（診断が、認証情報を漏らす側になってしまうため。gitleaks と同じ方針）。
キー名だけを示し、値は伏せる。
"""
from app.codescan.iac_rules.common import ERROR, INFO, WARNING, IacIssue
from app.codescan.iac_rules.compose import check_docker_compose
from app.codescan.iac_rules.dockerfile import check_dockerfile
from app.codescan.iac_rules.firebase import (
    check_firebase_json,
    check_firebase_rules,
    check_realtime_db_rules,
)

__all__ = [
    "ERROR", "INFO", "WARNING", "IacIssue", "check_docker_compose", "check_dockerfile",
    "check_firebase_json", "check_firebase_rules", "check_realtime_db_rules",
]
