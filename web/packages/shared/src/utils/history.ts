// 只接收本应用的路径，避免登录回跳成为开放重定向，也不回到登录页形成循环。
export function safeReturnPath(value: unknown, fallback: string): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000-\u001f]/.test(value))
    return fallback;
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return fallback;
  }
  if (decoded.startsWith('//') || /[\\\u0000-\u001f]/.test(decoded)) return fallback;
  const url = new URL(value, 'https://starbeacon.invalid');
  if (url.origin !== 'https://starbeacon.invalid' || /^\/login(?:\/|$)/.test(url.pathname)) return fallback;
  return url.pathname + url.search + url.hash;
}
