import { readonly, shallowRef } from 'vue'
import type { Principal } from './types'

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly requestId = '') {super(message)}
}
export class ApiClient {
  private csrf = ''
  onUnauthorized?: () => void
  constructor(readonly prefix: string) {}
  setCSRF(value: string) {this.csrf = value}
  async request<T>(path: string, options: {method?: string; body?: unknown; signal?: AbortSignal} = {}): Promise<T> {
    const response = await fetch(this.prefix + path, {method: options.method ?? 'GET', credentials: 'same-origin', signal: options.signal, headers: {'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf}, body: options.body == null ? undefined : JSON.stringify(options.body)})
    const body = await response.json().catch(() => ({}))
    if (!response.ok) {
      if (response.status === 401 && path !== '/auth/login') this.onUnauthorized?.()
      throw new ApiError(response.status, body.code ?? 'request_failed', body.message ?? '请求失败，请稍后重试', body.request_id)
    }
    return body as T
  }
}
export function createSession(prefix: string) {
  const api = new ApiClient(prefix)
  const current = shallowRef<Principal | null>(null)
  const pending = shallowRef(false)
  const error = shallowRef('')
  let initialized = false
  let bootstrap: Promise<void> | undefined
  api.onUnauthorized = () => {current.value = null; api.setCSRF(''); initialized = false}
  async function restore() {
    if (initialized) return
    if (bootstrap) return bootstrap
    bootstrap = (async () => {try {current.value = await api.request<Principal>('/auth/me'); api.setCSRF(current.value.csrf_token)} catch (e) {if (!(e instanceof ApiError && e.status === 401)) throw e} finally {bootstrap = undefined}})()
    await bootstrap
    initialized = true
  }
  async function login(username: string, password: string) {
    pending.value = true; error.value = ''
    try {current.value = await api.request<Principal>('/auth/login', {method: 'POST', body: {username, password}}); api.setCSRF(current.value.csrf_token); initialized = true; return true} catch (e) {error.value = e instanceof Error ? e.message : '登录失败'; return false} finally {pending.value = false}
  }
  async function logout() {await api.request('/auth/logout', {method: 'POST', body: {}}); current.value = null; api.setCSRF('')}
  return {api, current: readonly(current), pending: readonly(pending), error: readonly(error), restore, login, logout}
}
