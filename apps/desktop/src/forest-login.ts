/** Loopback OAuth sign-in against a local forest gateway. */

import { createHash, randomBytes } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** PKCE verifier and S256 challenge, both base64url without padding. */
export function createPkce(): { verifier: string, challenge: string } {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge }
}

/**
 * Replace named assignments and append the ones that were absent.
 * @param text - existing dotenv text, possibly empty.
 * @param updates - keys written without quotes. Values cannot contain line breaks.
 * @returns the next dotenv document, ending in a newline.
 */
export function mergeUserEnv(text: string, updates: Record<string, string>): string {
  for (const value of Object.values(updates)) {
    if (value.includes('\n') || value.includes('\r')) throw new Error('forest: credential value cannot span lines')
  }
  const lines = text === '' ? [] : text.split('\n')
  const seen = new Set<string>()
  const out = lines.map(line => {
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=/.exec(line)
    const name = match?.[1]
    if (name === undefined || !(name in updates)) return line
    seen.add(name)
    return `${name}=${updates[name]}`
  })
  while (out.length > 0 && out[out.length - 1] === '') out.pop()
  for (const [key, value] of Object.entries(updates)) {
    if (!seen.has(key)) out.push(`${key}=${value}`)
  }
  return out.length === 0 ? '' : `${out.join('\n')}\n`
}

/** Harness home that already loads `DEEPSEEK_API_KEY`. */
export function forestHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.DSH_HOME !== undefined && env.DSH_HOME.length > 0 ? env.DSH_HOME : join(homedir(), '.dsh')
}

/** Drop named assignments. Other lines, including blanks and comments, stay. */
export function removeUserEnv(text: string, names: readonly string[]): string {
  const drop = new Set(names)
  const lines = text === '' ? [] : text.split('\n')
  const out = lines.filter(line => {
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=/.exec(line)
    const name = match?.[1]
    return name === undefined || !drop.has(name)
  })
  while (out.length > 0 && out[out.length - 1] === '') out.pop()
  return out.length === 0 ? '' : `${out.join('\n')}\n`
}

/** Accept an http(s) gateway address and drop a trailing slash. */
export function normalizeForestBaseURL(baseURL: string): string {
  const value = baseURL.trim().replace(/\/+$/u, '')
  if (!/^https?:\/\/[A-Za-z0-9._:-]+(?:\/[^\s]*)?$/u.test(value)) {
    throw new Error('forest: base URL is not a usable address')
  }
  return value
}

const forestBaseName = 'forest-base-url'

/** Read the gateway address the desktop shell passes into the host process. */
export async function readForestBaseURL(home: string): Promise<string | undefined> {
  let text = ''
  try {
    text = await readFile(join(home, forestBaseName), 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  if (text.trim() === '') return undefined
  return normalizeForestBaseURL(text)
}

/**
 * Replace a version-1 `refs.DEEPSEEK_API_KEY` scalar.
 * @param text - credentials document.
 * @param apiKey - forest key. Only unquoted URL-safe characters are written.
 * @returns the next document, `absent` when that ref is not stored, or `unsafe` when the line cannot be replaced without rewriting the file.
 */
export function replaceStoredApiKey(text: string, apiKey: string): { status: 'updated' | 'absent' | 'unsafe', text: string } {
  if (!/^[A-Za-z0-9_-]+$/u.test(apiKey)) return { status: 'unsafe', text }
  const versionOk = text.split('\n').some(line => /^version:[ \t]*1[ \t]*$/u.test(line))
  let inRefs = false
  let refsIndent = 0
  let sawKey = false
  let updated = false
  const looseKey = (line: string): void => {
    if (/^DEEPSEEK_API_KEY[ \t]*:/u.test(line)) sawKey = true
  }
  const out = text.split('\n').map(line => {
    if (!inRefs) {
      looseKey(line)
      const header = /^( *)refs:[ \t]*(?:#.*)?$/u.exec(line)
      if (header !== null) {
        inRefs = true
        refsIndent = header[1]!.length
      }
      return line
    }
    if (line.trim() === '' || /^[ \t]*#/u.test(line)) return line
    const indent = /^( *)/u.exec(line)![1]!.length
    if (indent <= refsIndent) {
      inRefs = false
      looseKey(line)
      return line
    }
    if (!/^( +)DEEPSEEK_API_KEY[ \t]*:/u.test(line)) return line
    sawKey = true
    const match = /^( +)DEEPSEEK_API_KEY:[ \t]+\S+[ \t]*$/u.exec(line)
    if (!versionOk || match === null || updated) return line
    updated = true
    return `${match[1]}DEEPSEEK_API_KEY: ${apiKey}`
  })
  if (updated) return { status: 'updated', text: out.join('\n') }
  if (sawKey) return { status: 'unsafe', text }
  return { status: 'absent', text }
}

/**
 * Write the API key into the user env layer and the gateway address beside it.
 * `DEEPSEEK_BASE_URL` is refused in every `.env`, so the desktop shell reads `forest-base-url` and exports it when it launches the host.
 * A stored key, when present, is replaced in place.
 */
export async function writeForestCredentials(home: string, baseURL: string, apiKey: string): Promise<void> {
  const normalized = normalizeForestBaseURL(baseURL)
  await mkdir(home, { recursive: true, mode: 0o700 })
  const credentialsPath = join(home, '.credentials.yaml')
  let credentials = ''
  let credentialsExist = true
  try {
    credentials = await readFile(credentialsPath, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    credentialsExist = false
  }
  if (credentialsExist) {
    const edited = replaceStoredApiKey(credentials, apiKey)
    if (edited.status === 'unsafe') throw new Error('forest: stored DEEPSEEK_API_KEY could not be updated safely')
    if (edited.status === 'updated') await writeFile(credentialsPath, edited.text, { mode: 0o600 })
  }
  const path = join(home, '.env')
  let text = ''
  try {
    text = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  await writeFile(path, removeUserEnv(mergeUserEnv(text, { DEEPSEEK_API_KEY: apiKey }), ['DEEPSEEK_BASE_URL']), { mode: 0o600 })
  await writeFile(join(home, forestBaseName), `${normalized}\n`, { mode: 0o600 })
}

/** Finish the browser login and return the new gateway key. The key is not logged. */
export async function completeForestSignIn(options: {
  baseURL: string
  open: (url: string) => Promise<void>
  timeoutMs?: number
}): Promise<{ apiKey: string, prefix: string }> {
  const baseURL = options.baseURL.replace(/\/+$/u, '')
  const { verifier, challenge } = createPkce()
  const state = randomBytes(16).toString('base64url')
  const granted = await waitForAuthorization({
    state, challenge, timeoutMs: options.timeoutMs ?? 5 * 60 * 1000, open: options.open, baseURL,
  })
  const tokenResponse = await fetch(`${baseURL}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: 'forest-desktop',
      code: granted.code, code_verifier: verifier, redirect_uri: granted.redirectURI,
    }),
  })
  if (!tokenResponse.ok) throw new Error(`forest: token exchange failed (${tokenResponse.status})`)
  const token = await tokenResponse.json() as { access_token?: string }
  if (token.access_token === undefined || token.access_token.length === 0) {
    throw new Error('forest: token exchange returned no access token')
  }
  const keyResponse = await fetch(`${baseURL}/api/keys`, {
    method: 'POST', headers: { authorization: `Bearer ${token.access_token}` },
  })
  if (!keyResponse.ok) throw new Error(`forest: API key request failed (${keyResponse.status})`)
  const minted = await keyResponse.json() as { api_key?: string, prefix?: string }
  if (minted.api_key === undefined || minted.prefix === undefined) throw new Error('forest: API key response was incomplete')
  return { apiKey: minted.api_key, prefix: minted.prefix }
}

function waitForAuthorization(options: {
  baseURL: string
  state: string
  challenge: string
  timeoutMs: number
  open: (url: string) => Promise<void>
}): Promise<{ code: string, redirectURI: string }> {
  return new Promise((resolve, reject) => {
    let redirectURI = ''
    let settled = false
    const finish = (error: Error | undefined, value?: { code: string, redirectURI: string }): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      server.close()
      if (error !== undefined) reject(error)
      else resolve(value!)
    }
    const server: Server = createServer((request, response) => {
      const url = new URL(request.url ?? '/', 'http://127.0.0.1')
      if (url.pathname !== '/callback') {
        response.writeHead(404)
        response.end()
        return
      }
      const code = url.searchParams.get('code')
      const returned = url.searchParams.get('state')
      const ok = code !== null && returned === options.state
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      response.end(ok
        ? '<p>Forest 登录完成，可以回到 DeepSeek Harness。</p>'
        : '<p>登录没有完成。</p>')
      finish(ok && code !== null ? undefined : new Error('forest: authorization response was rejected'),
        ok && code !== null ? { code, redirectURI } : undefined)
    })
    const timer = setTimeout(() => { finish(new Error('forest: sign-in timed out')) }, options.timeoutMs)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        finish(new Error('forest: loopback failed'))
        return
      }
      redirectURI = `http://127.0.0.1:${address.port}/callback`
      const authorize = `${options.baseURL}/oauth/authorize?response_type=code&client_id=forest-desktop&code_challenge_method=S256`
        + `&code_challenge=${encodeURIComponent(options.challenge)}&redirect_uri=${encodeURIComponent(redirectURI)}&state=${encodeURIComponent(options.state)}`
      void options.open(authorize).catch((error: unknown) => {
        finish(error instanceof Error ? error : new Error('forest: browser did not open'))
      })
    })
  })
}
