"""通知の共通フロー（`Notifier`。Template Method）と、クローラー種別ごとの表示設定。"""
from abc import ABC, abstractmethod

from app.core.notifications import slack

# クローラー種別ごとの表示設定（絵文字, ラベル）
CRAWLER_LABELS: dict[str, tuple[str, str]] = {
    "KEV": (":shield:", "CISA KEV"),
    "OSV": (":package:", "OSV 脆弱性データ"),
    "JVN": (":jigsaw:", "JVN 脆弱性データ"),
    "DEPSCAN": (":rotating_light:", "依存ライブラリ脆弱性"),
    "DEPSOPS": (":robot_face:", "Dependabot PR 自動運用"),
    "CODESCAN": (":mag:", "自アプリコード脆弱性"),
    "RUNTIME": (":arrows_counterclockwise:", "言語・実行環境のバージョン"),
    "GHALERT": (":lock:", "GitHub のセキュリティアラート"),
    "REPOAUDIT": (":clipboard:", "リポジトリの設定の監査"),
    "EXTMON": (":globe_with_meridians:", "公開サイトの外形監視"),
    "COMMITWATCH": (":detective:", "コミットの監視"),
}


class Notifier(ABC):
    """Slack 通知の共通フロー（Template Method）。

    「送るべき内容があるか判定 → 送信先を解決 → メッセージを組み立て → 全送信先へ送る」という
    流れを `send` に集約し、サブクラスは次の3点だけを差し替える。

    - `has_content`: 通知すべき内容があるか（変化なし・0件のときは送らない）
    - `default_recipients`: `recipients` 省略時の送信先（既定経路）
    - `build_message`: Slack に送る本文
    """

    def __init__(self, recipients: list[str] | None = None) -> None:
        # 送信先を明示指定する場合（登録済み他ユーザーの個別クロール結果を本人にだけ送る等）
        self._recipients = recipients

    @abstractmethod
    def has_content(self) -> bool:
        """通知すべき内容があるか。False なら送信先の解決もせずに終了する。"""

    @abstractmethod
    def default_recipients(self) -> list[str]:
        """`recipients` 未指定時の送信先URL一覧（毎日クロールが呼ぶ既定の経路）。"""

    @abstractmethod
    def build_message(self) -> str:
        """Slack に送る本文を組み立てる。"""

    def send(self) -> bool:
        """通知を送る。送信先すべてへの送信に成功したら True（送るものが無い・失敗があれば False）。

        毎日クロールの呼び出しは戻り値を使わないが、期限通知・テスト送信のように成否で次の処理を
        決める呼び出し側のために返す。"""
        if not self.has_content():
            return False
        targets = self.default_recipients() if self._recipients is None else self._recipients
        if not targets:
            return False
        message = self.build_message()
        # 1件失敗しても残りへは送る（短絡評価しない）
        results = [slack.send_slack(message, url) for url in targets]
        return all(results)
