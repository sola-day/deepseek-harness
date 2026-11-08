import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it, onTestFinished } from 'vitest'
import { createPkce, mergeUserEnv, readForestBaseURL, replaceStoredApiKey, writeForestCredentials } from '../src/forest-login.ts'

it('replaces existing assignments and keeps the rest of the user env', () => {
  const next = mergeUserEnv('OTHER=1\nexport DEEPSEEK_API_KEY=old\nDEEPSEEK_BASE_URL=https://api.deepseek.com\n', {
    DEEPSEEK_API_KEY: 'fr_new', DEEPSEEK_BASE_URL: 'http://127.0.0.1:8787',
  })
  expect(next).toBe('OTHER=1\nDEEPSEEK_API_KEY=fr_new\nDEEPSEEK_BASE_URL=http://127.0.0.1:8787\n')
})

it('writes the gateway key into a private user env file and keeps the base URL out of it', async () => {
  const home = mkdtempSync(join(tmpdir(), 'forest-home-'))
  onTestFinished(() => { rmSync(home, { recursive: true, force: true }) })
  writeFileSync(join(home, '.env'), 'OTHER=1\nDEEPSEEK_BASE_URL=https://api.deepseek.com\n')
  await writeForestCredentials(home, 'http://127.0.0.1:8787/', 'fr_test_key')
  expect(readFileSync(join(home, '.env'), 'utf8')).toBe('OTHER=1\nDEEPSEEK_API_KEY=fr_test_key\n')
  expect(readFileSync(join(home, 'forest-base-url'), 'utf8')).toBe('http://127.0.0.1:8787\n')
  expect(await readForestBaseURL(home)).toBe('http://127.0.0.1:8787')
  const { verifier, challenge } = createPkce()
  expect(verifier.length).toBeGreaterThan(20)
  expect(challenge).not.toBe(verifier)
})

it('replaces a stored API key and leaves the rest of the credentials file', async () => {
  const home = mkdtempSync(join(tmpdir(), 'forest-home-'))
  onTestFinished(() => { rmSync(home, { recursive: true, force: true }) })
  const original = 'version: 1\nrefs:\n  OPENAI_API_KEY: sk-other\n  DEEPSEEK_API_KEY: sk-old\nrecords:\n  llm-pi-ai/openai-codex:\n    kind: grant\n'
  writeFileSync(join(home, '.credentials.yaml'), original)
  await writeForestCredentials(home, 'http://127.0.0.1:8787', 'fr_test_key')
  expect(readFileSync(join(home, '.credentials.yaml'), 'utf8')).toBe(
    'version: 1\nrefs:\n  OPENAI_API_KEY: sk-other\n  DEEPSEEK_API_KEY: fr_test_key\nrecords:\n  llm-pi-ai/openai-codex:\n    kind: grant\n',
  )
  expect(replaceStoredApiKey('DEEPSEEK_API_KEY: sk-old\n', 'fr_test_key').status).toBe('unsafe')
})
