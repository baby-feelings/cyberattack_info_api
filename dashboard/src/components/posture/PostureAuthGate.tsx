import { GithubLoginGate } from '../shared/GithubLoginGate'
import { PosturePanel } from './PosturePanel'
import { POSTURE_TEXT } from './postureConfig'

// 「態勢」タブの GitHub ログインゲート。ログイン後は、本人所有のリポジトリの結果だけが返る（サーバー側で絞り込む）。
export function PostureAuthGate() {
  return (
    <GithubLoginGate description={POSTURE_TEXT.loginDescription}>
      {(session) => <PosturePanel authToken={session.token} />}
    </GithubLoginGate>
  )
}
