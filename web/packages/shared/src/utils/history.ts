// 只接收本应用的路径，避免登录回跳成为开放重定向。
export function safeReturnPath(value: unknown, fallback: string, allowLogin = false): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000-\u001f]/.test(value)) return fallback
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { return fallback }
  if (decoded.startsWith('//') || /[\\\u0000-\u001f]/.test(decoded)) return fallback
  const url = new URL(value, 'https://starbeacon.invalid')
  if (url.origin !== 'https://starbeacon.invalid' || (!allowLogin && /^\/login(?:\/|$)/.test(url.pathname))) return fallback
  return url.pathname + url.search + url.hash
}

export function migrateLegacyHash(base = '/') {
  if (!window.location.hash.startsWith('#/')) return
  const target = safeReturnPath(window.location.hash.slice(1), '/', true)
  const prefix = base.replace(/\/$/, '')
  window.history.replaceState(window.history.state, '', prefix + target)
}
