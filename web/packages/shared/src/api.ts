import { readonly, shallowRef } from 'vue'
import type { Principal,SearchRequest } from './types'
import {instant} from './utils/instant'
import {validSessionReport,type SessionExportRequest,type SessionExportReport} from './packetArchives'

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly requestId = '',readonly details:Readonly<Record<string,string>>={}) {super(message)}
}
export class SessionExportError extends ApiError {
  constructor(message:string,readonly report:SessionExportReport,requestId=''){super(422,'session_incomplete',message,requestId)}
}
export class ApiClient {
  private csrf = ''
  private authEpoch = 0
  onUnauthorized?: () => void
  constructor(readonly prefix: string) {}
  private async fetch(path:string,options:RequestInit):Promise<Response>{
    try{return await fetch(this.prefix+path,options)}catch(error){if(error instanceof TypeError&&!options.signal?.aborted)throw new ApiError(0,'network_unavailable','无法连接服务，请检查网络后重试');throw error}
  }
  setCSRF(value: string) {this.csrf = value;this.authEpoch++}
  async request<T>(path: string, options: {method?: string; body?: unknown; file?: File; signal?: AbortSignal; headers?: Record<string,string>} = {}): Promise<T> {
    const authEpoch=this.authEpoch
    const response = await this.fetch(path, {method: options.method ?? 'GET', credentials: 'same-origin', signal: options.signal, headers: {...options.headers, 'Content-Type': options.file?'application/octet-stream':'application/json', 'X-CSRF-Token': this.csrf,...(options.file?{'X-Filename':encodeURIComponent(options.file.name)}:{})}, body: options.file??(options.body == null ? undefined : JSON.stringify(options.body))})
    const raw = await response.json().catch(() => ({})),body=raw&&typeof raw==='object'?raw:{}
    if (!response.ok) {
      if (response.status === 401 && path !== '/auth/login' && authEpoch===this.authEpoch) this.onUnauthorized?.()
      const details=typeof body.related_incident_id==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(body.related_incident_id)?Object.freeze({related_incident_id:body.related_incident_id}):{}
      throw new ApiError(response.status, body.code ?? 'request_failed', body.message ?? '请求失败，请稍后重试', body.request_id,details)
    }
    return body as T
  }
  async download(path:string,signal?:AbortSignal):Promise<Blob>{
    const epoch=this.authEpoch,response=await this.fetch(path,{credentials:'same-origin',signal})
    if(!response.ok){const raw=await response.json().catch(()=>({})),body=raw&&typeof raw==='object'?raw:{};if(response.status===401&&epoch===this.authEpoch)this.onUnauthorized?.();throw new ApiError(response.status,body.code??'export_failed',body.message??'报告导出失败，请稍后重试',body.request_id)}
    if(!response.headers.get('Content-Type')?.startsWith('text/html'))throw new ApiError(502,'invalid_export','报告导出内容不完整')
    const blob=await response.blob();if(blob.size>2*1024*1024)throw new ApiError(413,'export_too_large','报告超过导出大小限制');return blob
  }

  async downloadPacket(path:string,signal?:AbortSignal,submission?:SessionExportRequest):Promise<Blob>{
    const epoch=this.authEpoch,response=await this.fetch(path,{method:submission?'POST':'GET',credentials:'same-origin',signal,...(submission?{headers:{'Content-Type':'application/json','X-CSRF-Token':this.csrf},body:JSON.stringify(submission)}:{})})
    if(!response.ok){const raw=await response.json().catch(()=>({})),body=raw&&typeof raw==='object'?raw:{};if(response.status===401&&epoch===this.authEpoch)this.onUnauthorized?.();if(response.status===422&&body.code==='session_incomplete'&&validSessionReport(body.report))throw new SessionExportError(body.message??'所选原包未满足导出条件',body.report,body.request_id);throw new ApiError(response.status,body.code??'packet_download_failed',body.message??'原包下载失败，请稍后重试',body.request_id)}
    if(submission&&response.headers.get('X-Session-Completeness')!==submission.mode){await response.body?.cancel();throw new ApiError(502,'invalid_session_export','会话导出范围与所选模式不一致，请重新核查')}
    return this.verifiedFile(response,signal,epoch,{type:'application/x-pcapng',min:24,max:64*1024*1024,label:'原包',code:'invalid_packet_download',unavailable:'packet_verification_unavailable'})
  }

  async downloadSearch(dataset:'alerts'|'context',query:SearchRequest,signal?:AbortSignal):Promise<{blob:Blob;rows:number}>{
    const epoch=this.authEpoch,response=await this.fetch(dataset==='alerts'?'/alerts/export':'/traffic/export',{method:'POST',credentials:'same-origin',signal,headers:{'Content-Type':'application/json','X-CSRF-Token':this.csrf},body:JSON.stringify(query)})
    if(!response.ok){const raw=await response.json().catch(()=>({})),body=raw&&typeof raw==='object'?raw:{};if(response.status===401&&epoch===this.authEpoch)this.onUnauthorized?.();throw new ApiError(response.status,body.code??'search_export_failed',body.message??'检索导出未完成，请稍后重试',body.request_id)}
    const rowText=response.headers.get('X-Export-Rows')??'',rows=Number(rowText),start=instant(query.start),end=instant(query.end)
    if(response.headers.get('X-Export-Dataset')!==dataset||!/^(0|[1-9]\d{0,4})$/.test(rowText)||rows>10000||start===null||end===null||instant(response.headers.get('X-Export-Start')??'')!==start||instant(response.headers.get('X-Export-End')??'')!==end){await response.body?.cancel();throw new ApiError(502,'invalid_search_export','检索导出范围或记录数量与当前请求不一致')}
    const blob=await this.verifiedFile(response,signal,epoch,{type:'text/csv',min:3,max:8*1024*1024,label:'检索文件',code:'invalid_search_export',unavailable:'export_verification_unavailable'})
    const prefix=new Uint8Array(await blob.slice(0,3).arrayBuffer())
    if(prefix[0]!==239||prefix[1]!==187||prefix[2]!==191)throw new ApiError(502,'invalid_search_export','检索导出文件编码不符合 UTF-8 契约')
    if(signal?.aborted)throw new DOMException('检索导出已取消','AbortError')
    if(epoch!==this.authEpoch)throw new ApiError(409,'session_changed','登录会话已变化，请重新导出检索结果')
    return {blob,rows}
  }

  private async verifiedFile(response:Response,signal:AbortSignal|undefined,epoch:number,options:{type:string;min:number;max:number;label:string;code:string;unavailable:string}):Promise<Blob>{
    const {type,min,max,label,code,unavailable}=options,sizeText=response.headers.get('Content-Length')??'',digest=response.headers.get('X-Content-SHA256')??'',size=Number(sizeText)
    if(response.headers.get('Content-Type')?.split(';')[0]!==type||!/^\d+$/.test(sizeText)||!Number.isSafeInteger(size)||size<min||size>max||!/^[a-f0-9]{64}$/.test(digest)||!response.body){await response.body?.cancel();throw new ApiError(502,code,`${label}下载的类型、长度或摘要不完整`)}
    if(!crypto.subtle){await response.body.cancel();throw new ApiError(503,unavailable,`当前浏览器无法验证${label}摘要，请通过 HTTPS 或本机安全入口访问`)}
    const reader=response.body.getReader(),hashInput=new Uint8Array(size)
    let received=0
    try{
      for(;;){if(signal?.aborted)throw new DOMException(`${label}下载已取消`,'AbortError');const {done,value}=await reader.read();if(done)break;if(value.length>size-received)throw new ApiError(502,code,`${label}下载长度与冻结目录不一致`);hashInput.set(value,received);received+=value.length}
      if(received!==size)throw new ApiError(502,code,`${label}下载尚未完整接收，请重试`)
      const actual=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',hashInput)),byte=>byte.toString(16).padStart(2,'0')).join('')
      if(signal?.aborted)throw new DOMException(`${label}下载已取消`,'AbortError')
      if(epoch!==this.authEpoch)throw new ApiError(409,'session_changed',`登录会话已变化，请重新下载${label}`)
      if(actual!==digest)throw new ApiError(502,code,`${label} SHA-256 校验失败，请保留现场并重试`)
      return new Blob([hashInput],{type})
    }finally{await reader.cancel().catch(()=>{});reader.releaseLock()}
  }
}
export function createSession(prefix: string) {
  const api = new ApiClient(prefix)
  const current = shallowRef<Principal | null>(null)
  const pending = shallowRef(false)
  const error = shallowRef('')
  let initialized = false
  let bootstrap: Promise<void> | undefined
  let generation = 0
  api.onUnauthorized = () => {generation++; current.value = null; api.setCSRF(''); initialized = false; bootstrap = undefined}
  async function restore() {
    if (initialized) return
    if (bootstrap) return bootstrap
    const epoch = generation
    const request = (async () => {
      try {const principal = await api.request<Principal>('/auth/me'); if(epoch === generation) {current.value = principal; api.setCSRF(principal.csrf_token); initialized = true}}
      catch (e) {if(epoch === generation && !(e instanceof ApiError && e.status === 401)) throw e}
      finally {if(epoch === generation) bootstrap = undefined}
    })()
    bootstrap = request
    await request
  }
  async function login(username: string, password: string) {
    if(pending.value) return false
    generation++; bootstrap = undefined; initialized = false; current.value = null; api.setCSRF('')
    pending.value = true; error.value = ''
    try {current.value = await api.request<Principal>('/auth/login', {method: 'POST', body: {username, password}}); api.setCSRF(current.value.csrf_token); initialized = true; return true} catch (e) {error.value = e instanceof Error ? e.message : '登录失败'; return false} finally {pending.value = false}
  }
  async function logout() {
    if(pending.value) return
    generation++; bootstrap = undefined; pending.value = true
    try {await api.request('/auth/logout', {method: 'POST', body: {}}); current.value = null; api.setCSRF(''); initialized = false}
    finally {pending.value = false}
  }
  return {api, current: readonly(current), pending: readonly(pending), error: readonly(error), restore, login, logout}
}
