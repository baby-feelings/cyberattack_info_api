import { describe, expect, it } from 'vitest'
import { githubPullUrl, githubRepoUrl, nvdUrl, osvUrl } from './externalLinks'

describe('externalLinks', () => {
  it('builds the NVD and OSV detail URLs', () => {
    expect(nvdUrl('CVE-2026-0001')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2026-0001')
    expect(osvUrl('GHSA-aaaa-bbbb-cccc')).toBe('https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc')
  })

  it('builds the GitHub repository and pull request URLs', () => {
    expect(githubRepoUrl('baby-feelings/baby_grow')).toBe('https://github.com/baby-feelings/baby_grow')
    expect(githubPullUrl('baby-feelings/baby_grow', 42)).toBe(
      'https://github.com/baby-feelings/baby_grow/pull/42',
    )
  })
})
