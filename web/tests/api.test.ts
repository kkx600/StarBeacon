import { describe, expect, it, vi } from 'vitest'
import { ApiClient, ApiError, createSession } from '../packages/shared/src/api'

const response=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}})
const user={id:'user_1',tenant_id:'tenant_1',username:'admin',role:'admin' as const,csrf_token:'csrf_1'}

describe('会话与 API 行为',()=>{
  it('仅保留有效的既有事件标识，错误回执不透传未知材料',async()=>{
    vi.stubGlobal('fetch',vi.fn().mockResolvedValueOnce(response({code:'alert_already_linked',message:'告警已关联事件',related_incident_id:'incident_owned',secret:'must_not_expose'},409)).mockResolvedValueOnce(response({code:'alert_already_linked',message:'告警已关联事件',related_incident_id:'foreign/id'},409)));const api=new ApiClient('/api')
    await expect(api.request('/incidents')).rejects.toMatchObject({details:{related_incident_id:'incident_owned'}});await expect(api.request('/incidents')).rejects.toMatchObject({details:{}})
  })
  it('网络连接失败使用中文提示，取消不被转换成连接故障',async()=>{
    const aborted=new AbortController();aborted.abort();const cancellation=new DOMException('aborted','AbortError')
    vi.stubGlobal('fetch',vi.fn().mockRejectedValueOnce(new TypeError('Failed to fetch')).mockRejectedValueOnce(new TypeError('NetworkError')).mockRejectedValueOnce(cancellation).mockResolvedValueOnce(response(null,503)))
    const api=new ApiClient('/api');await expect(api.request('/objects')).rejects.toMatchObject({status:0,code:'network_unavailable',message:'无法连接服务，请检查网络后重试'});await expect(api.download('/report')).rejects.toMatchObject({code:'network_unavailable'});await expect(api.request('/objects',{signal:aborted.signal})).rejects.toBe(cancellation);await expect(api.request('/objects')).rejects.toMatchObject({status:503,message:'请求失败，请稍后重试'})
  })
  it('报告下载使用同源身份，验证内容类型并保留错误状态',async()=>{
    const fetcher=vi.fn().mockResolvedValueOnce(new Response('<html>report</html>',{headers:{'Content-Type':'text/html; charset=utf-8'}})).mockResolvedValueOnce(response({},200)).mockResolvedValueOnce(new Response('proxy error',{status:503})).mockResolvedValueOnce(response({message:'无权限',code:'denied'},403));vi.stubGlobal('fetch',fetcher);const api=new ApiClient('/api'),signal=new AbortController().signal
    expect((await api.download('/report',signal)).size).toBeGreaterThan(0);expect(fetcher.mock.calls[0]).toEqual(['/api/report',{credentials:'same-origin',signal}]);await expect(api.download('/report')).rejects.toMatchObject({code:'invalid_export'});await expect(api.download('/report')).rejects.toMatchObject({message:'报告导出失败，请稍后重试'});await expect(api.download('/report')).rejects.toMatchObject({status:403,code:'denied'})
  })
  it('过期下载不会覆盖新的会话，超大报告不触发保存',async()=>{
    let finish!:(value:Response)=>void;const fetcher=vi.fn().mockImplementationOnce(()=>new Promise<Response>(resolve=>{finish=resolve})).mockResolvedValueOnce(response({},401)).mockResolvedValueOnce(new Response('x'.repeat(2*1024*1024+1),{headers:{'Content-Type':'text/html'}}));vi.stubGlobal('fetch',fetcher);const api=new ApiClient('/api'),unauthorized=vi.fn();api.onUnauthorized=unauthorized;const old=api.download('/report');api.setCSRF('new');finish(response({},401));await expect(old).rejects.toThrow();expect(unauthorized).not.toHaveBeenCalled();await expect(api.download('/report')).rejects.toThrow();expect(unauthorized).toHaveBeenCalledOnce();await expect(api.download('/report')).rejects.toMatchObject({code:'export_too_large'})
  })
  it('只通过同源 Cookie 请求，写请求携带内存 CSRF 并保留取消信号',async()=>{
    const fetcher=vi.fn().mockResolvedValue(response({ok:true}));vi.stubGlobal('fetch',fetcher)
    const api=new ApiClient('/api/v1'),controller=new AbortController();api.setCSRF('csrf')
    expect(await api.request('/objects',{method:'POST',body:{x:1},signal:controller.signal,headers:{'Idempotency-Key':'key'}})).toEqual({ok:true})
    expect(fetcher).toHaveBeenCalledWith('/api/v1/objects',expect.objectContaining({method:'POST',body:'{"x":1}',credentials:'same-origin',signal:controller.signal,headers:expect.objectContaining({'X-CSRF-Token':'csrf','Idempotency-Key':'key'})}))
    const file=new File(['bytes'],'证据.pcap');await api.request('/samples',{method:'POST',file})
    expect(fetcher.mock.lastCall?.[1]).toMatchObject({body:file,headers:{'Content-Type':'application/octet-stream','X-Filename':encodeURIComponent(file.name)}})
    await api.request('/objects');expect(fetcher.mock.lastCall?.[1]).toMatchObject({method:'GET',body:undefined})
  })
  it('登录失败保留错误信息，过期会话失效，非 JSON 错误有可读提示',async()=>{
    const fetcher=vi.fn().mockResolvedValueOnce(response({message:'凭据无效',code:'invalid_credentials'},401)).mockResolvedValueOnce(new Response('proxy error',{status:503})).mockResolvedValueOnce(response({request_id:'req',message:'会话已过期',code:'unauthenticated'},401));vi.stubGlobal('fetch',fetcher)
    const api=new ApiClient('/api'),unauthorized=vi.fn();api.onUnauthorized=unauthorized
    await expect(api.request('/auth/login')).rejects.toMatchObject({status:401,code:'invalid_credentials',message:'凭据无效'})
    expect(unauthorized).not.toHaveBeenCalled()
    await expect(api.request('/objects')).rejects.toBeInstanceOf(ApiError)
    await expect(api.request('/auth/me')).rejects.toMatchObject({requestId:'req'})
    expect(unauthorized).toHaveBeenCalledOnce()
  })
  it('合并并发恢复请求，登录退出清除身份和 CSRF',async()=>{
    const fetcher=vi.fn().mockResolvedValueOnce(response(user)).mockResolvedValueOnce(response(user)).mockResolvedValue(response({ok:true}));vi.stubGlobal('fetch',fetcher)
    const session=createSession('/api')
    await Promise.all([session.restore(),session.restore()]);expect(fetcher).toHaveBeenCalledOnce();await session.restore();expect(fetcher).toHaveBeenCalledOnce()
    expect(session.current.value).toEqual(user);expect(await session.login('admin','secret')).toBe(true)
    expect(session.pending.value).toBe(false);expect(session.error.value).toBe('')
    await session.logout();expect(session.current.value).toBeNull()
    await session.api.request('/objects');expect(fetcher.mock.lastCall?.[1].headers['X-CSRF-Token']).toBe('')
  })
  it('匿名恢复与依赖失败分别处理，失败恢复允许重试',async()=>{
    const fetcher=vi.fn().mockResolvedValueOnce(response({},401)).mockRejectedValueOnce(new Error('网络异常')).mockResolvedValueOnce(response(user)).mockRejectedValueOnce(new Error('密码无效'));vi.stubGlobal('fetch',fetcher)
    const anonymous=createSession('/api');await anonymous.restore();expect(anonymous.current.value).toBeNull()
    const failed=createSession('/api');await expect(failed.restore()).rejects.toThrow('网络异常');await failed.restore();expect(failed.current.value).toEqual(user)
    expect(await failed.login('admin','bad')).toBe(false);expect(failed.error.value).toBe('密码无效');expect(failed.pending.value).toBe(false)
  })
  it('鉴权失效会清除旧身份并允许重新恢复',async()=>{
    const fetcher=vi.fn().mockResolvedValueOnce(response(user)).mockResolvedValueOnce(response({},401)).mockResolvedValueOnce(response(user));vi.stubGlobal('fetch',fetcher)
    const session=createSession('/api');await session.restore();await expect(session.api.request('/objects')).rejects.toThrow();expect(session.current.value).toBeNull();await session.restore();expect(session.current.value).toEqual(user)
  })
  it('旧请求的 401 不能清除新登录产生的会话',async()=>{
    let finish:(response:Response)=>void=()=>{}
    const fetcher=vi.fn().mockImplementationOnce(()=>new Promise<Response>(resolve=>{finish=resolve})).mockResolvedValueOnce(response(user));vi.stubGlobal('fetch',fetcher)
    const session=createSession('/api'),old=session.api.request('/objects')
    expect(await session.login('admin','password')).toBe(true)
    finish(response({},401));await expect(old).rejects.toThrow();expect(session.current.value).toEqual(user)
  })
  it('退出后重新恢复会话必须重新请求服务器',async()=>{
    const fetcher=vi.fn().mockResolvedValueOnce(response(user)).mockResolvedValueOnce(response({ok:true})).mockResolvedValueOnce(response({},401));vi.stubGlobal('fetch',fetcher)
    const session=createSession('/api');await session.restore();await session.logout();await session.restore();expect(fetcher).toHaveBeenCalledTimes(3);expect(session.current.value).toBeNull()
  })
  it('迟到的恢复结果不能覆盖新登录，登录和退出请求不能并发重复提交',async()=>{
    let complete:(response:Response)=>void=()=>{}
    const fetcher=vi.fn().mockImplementationOnce(()=>new Promise<Response>(resolve=>{complete=resolve})).mockResolvedValueOnce(response({...user,id:'new_user'})).mockResolvedValueOnce(response({ok:true}));vi.stubGlobal('fetch',fetcher)
    const session=createSession('/api'),restore=session.restore();const login=session.login('admin','password');expect(await session.login('admin','duplicate')).toBe(false);await session.logout();expect(await login).toBe(true)
    complete(response(user));await restore;expect(session.current.value?.id).toBe('new_user');expect(fetcher).toHaveBeenCalledTimes(2)
    await session.logout();expect(session.current.value).toBeNull();expect(session.pending.value).toBe(false)
  })
  it('退出失败保留当前身份并恢复按钮，旧恢复错误不影响登录',async()=>{
    let reject:(error:Error)=>void=()=>{}
    const fetcher=vi.fn().mockImplementationOnce(()=>new Promise<Response>((_resolve,no)=>{reject=no})).mockResolvedValueOnce(response(user)).mockRejectedValueOnce(new Error('退出连接失败'));vi.stubGlobal('fetch',fetcher)
    const session=createSession('/api'),restore=session.restore();expect(await session.login('admin','password')).toBe(true);reject(new Error('旧错误'));await restore
    await expect(session.logout()).rejects.toThrow('退出连接失败');expect(session.current.value).toEqual(user);expect(session.pending.value).toBe(false)
  })
})
