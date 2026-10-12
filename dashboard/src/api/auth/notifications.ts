// Slack Webhook 通知登録（Issue #227）。

import { authorizedFetch } from './request'

export interface NotificationSettings {
  slack_webhook_url: string | null
  notifications_enabled: boolean
}

const PATH = '/auth/notification-settings'
const LABEL = 'Notification settings error'

export async function fetchNotificationSettings(authToken: string): Promise<NotificationSettings> {
  const res = await authorizedFetch(PATH, authToken, LABEL)
  return res.json()
}

// Webhook登録は必ずテスト送信を伴うため、URL形式不備・送信失敗はメッセージ付きの
// エラーとして呼び出し側（設定画面）へ伝える
export async function putNotificationSettings(
  authToken: string, slackWebhookUrl: string,
): Promise<NotificationSettings> {
  const res = await authorizedFetch(PATH, authToken, LABEL, {
    method: 'PUT',
    body: { slack_webhook_url: slackWebhookUrl },
    explain: 'any',
  })
  return res.json()
}

export async function deleteNotificationSettings(authToken: string): Promise<NotificationSettings> {
  const res = await authorizedFetch(PATH, authToken, LABEL, { method: 'DELETE' })
  return res.json()
}
