// タブ・小タブの文言（ラベル・見出し・説明・ログイン案内）。タブの構造（キー・本体・アイコン）は tabs.tsx、文言はここ。
// タブや小タブのキーを変えるときは、バックエンドの通知リンク（app/core/notifications/dashboard_links.py）も合わせる。
export const TAB_TEXT = {
  overview: { label: '概要' },
  public: {
    label: '公開情報',
    title: '公開情報 — 世界の公開された脆弱性',
    subtitle: 'CISA KEV（悪用が確認された脆弱性）と OSV（オープンソースの脆弱性）',
    kev: {
      label: 'KEV',
      title: 'CISA KEV — Known Exploited Vulnerabilities',
      subtitle: '実際に悪用が確認された脆弱性（米 CISA 公式カタログ）',
    },
    osv: {
      label: 'OSV',
      title: 'OSV — Open Source Vulnerabilities',
      subtitle: 'オープンソースライブラリの脆弱性（過去 6 ヶ月）',
    },
  },
  dependencies: {
    label: '依存ライブラリ',
    title: '依存ライブラリ — 脆弱性・対応状況・言語のサポート期限',
    subtitle: 'GitHub上の自作リポジトリの依存関係を OSV と照合し、悪意あるパッケージ・言語のサポート期限・対応状況・Dependabot も監視',
    login: 'ログインすると、あなた自身が所有する GitHub リポジトリの依存ライブラリ脆弱性を表示します',
    scan: {
      label: '検知',
      title: 'DEPSCAN — 自作アプリの依存ライブラリ脆弱性',
      subtitle: 'GitHub上の自作リポジトリの依存関係を OSV と照合し、悪意あるパッケージ・言語のサポート期限・対応状況も監視',
    },
    sla: { label: '対応状況' },
    depsops: { label: 'Dependabot運用' },
    deps: { label: '依存パッケージ' },
    runtimes: { label: '言語・実行環境' },
    alerts: {
      label: 'アラート',
      title: '依存ライブラリのアラート — Dependabot',
      subtitle: 'GitHub が検知した、依存ライブラリのセキュリティアラート',
    },
  },
  code: {
    label: 'コードと設定',
    title: 'コードと設定 — コードの診断・GitHub のアラート・リポジトリ設定の監査',
    subtitle: 'GitHub上の自作リポジトリのソースコード・設定を診断し、GitHub のセキュリティアラートとリポジトリ設定の監査も確認',
    login: 'ログインすると、自アプリのコード・設定の診断結果と、GitHub のアラート・リポジトリ設定の監査を閲覧できます',
    scan: {
      label: '検知',
      title: 'CODESCAN — 自アプリのコード脆弱性診断',
      subtitle: 'GitHub上の自作リポジトリのソースコードを静的解析し、GitHub Actions・Firebase・Dockerの設定も診断',
    },
    alerts: {
      label: 'アラート',
      title: 'コードのアラート — コードスキャン・シークレット',
      subtitle: 'GitHub が検知した、コードの脆弱性と、漏えいしたシークレットのアラート',
    },
    audit: {
      label: '設定の監査',
      title: 'リポジトリ設定の監査',
      subtitle: 'リポジトリ × 点検項目。項目を押すと、詳細と直し方が出ます',
    },
  },
  ops: {
    label: '運用',
    title: '運用 — 公開サイトの外形監視',
    subtitle: '公開サイトの TLS 証明書の期限・セキュリティヘッダー・露出ファイルなどを監視（本人所有のリポジトリ）',
    login: 'ログインすると、自分のリポジトリの公開サイトの外形監視の結果を閲覧できます',
  },
} as const
