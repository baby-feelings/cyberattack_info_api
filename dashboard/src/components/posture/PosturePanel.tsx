import { OperatingGroups } from './OperatingGroups'
import { PostureGroup } from './PostureGroup'

// 「態勢」タブ。運用中と運用停止中を、2つの区画に分けて同時に表示する（区画の仕組みは OperatingGroups）。
export function PosturePanel({ authToken }: { authToken: string }) {
  return (
    <OperatingGroups render={(operating) => <PostureGroup authToken={authToken} operating={operating} />} />
  )
}
