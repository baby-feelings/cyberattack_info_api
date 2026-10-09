"""ZAP のレポートから GitHub Issue を起票するコマンド。

使い方:
    python -m app.zapscan deploy/zap/reports/zap-report.json --min-risk 2

リポジトリは --repo、無ければ GitHub Actions の `GITHUB_REPOSITORY` 環境変数で決める。
トークンは設定の `GITHUB_TOKEN`（環境変数）を使う。
"""
import argparse
import logging
import os
import sys
from pathlib import Path

from app.zapscan.issue_management import RISK_LABELS, file_github_issues, parse_alerts

# GitHub Actions 以外で --repo を省略した場合の既定リポジトリ
_DEFAULT_REPO = "baby-feelings/cyberattack_info_api"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZAP の結果を GitHub Issue に起票する")
    parser.add_argument("report", type=Path, help="zap-report.json のパス")
    parser.add_argument(
        "--min-risk",
        type=int,
        default=2,
        choices=sorted(RISK_LABELS),
        help="起票する最小リスク（0=Info 1=Low 2=Medium 3=High。既定: 2）",
    )
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", _DEFAULT_REPO))
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # レポートが無い場合は早めに失敗させる（スキャン自体が失敗している可能性が高い）
    if not args.report.is_file():
        print(f"レポートが見つかりません: {args.report}", file=sys.stderr)
        return 1

    alerts = parse_alerts(args.report, args.min_risk)
    print(f"起票対象のアラート: {len(alerts)}件（{RISK_LABELS[args.min_risk]} 以上）")
    file_github_issues(alerts, args.repo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
