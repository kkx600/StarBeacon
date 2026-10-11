import {beforeEach,describe,expect,it,vi} from 'vitest'
import {Blob as NativeBlob} from 'node:buffer'
import {createHash,webcrypto} from 'node:crypto'
import {flushPromises,mount} from '@vue/test-utils'
import {shallowRef} from 'vue'
import {Modal} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiClient} from '../packages/shared/src/api'
import {instant} from '../packages/shared/src/utils/instant'
import type {SearchRequest} from '../packages/shared/src/types'
import SearchExportButton from '../platform/src/features/search/SearchExportButton.vue'
import {button,click,deferred,principal} from './fixtures'
const {download}=vi.hoisted(()=>({download:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{downloadSearch:download},get current(){return user}}}))
const query:SearchRequest={start:'2026-10-09T00:00:00.123456789Z',end:'2026-10-09T01:00:00.123456789Z',page:1,page_size:20,keyword:'',source_ip:'',destination_ip:'',protocol:'tcp',method:'',path:'',severity:'',filter:''}
const csv='\ufeff事件标识\r\nevent_owned\r\n'
function file(body=csv,overrides:Record<string,string>={}){
 const bytes=new TextEncoder().encode(body)
 return new Response(bytes,{headers:{'Content-Type':'text/csv; charset=utf-8','Content-Length':String(bytes.length),'X-Content-SHA256':createHash('sha256').update(bytes).digest('hex'),'X-Export-Rows':'1','X-Export-Dataset':'alerts','X-Export-Start':query.start,'X-Export-End':query.end,...overrides}})
}
beforeEach(()=>{user.value=principal;download.mockReset();vi.stubGlobal('Blob',NativeBlob);vi.stubGlobal('crypto',webcrypto)})

describe('检索文件下载契约',()=>{
 it('提交同源 CSRF 条件并校验真实字节、范围与两个数据集',async()=>{
  const fetcher=vi.fn().mockResolvedValueOnce(file()).mockResolvedValueOnce(file(csv,{'X-Export-Dataset':'context'}));vi.stubGlobal('fetch',fetcher)
  const api=new ApiClient('/api'),signal=new AbortController().signal;api.setCSRF('scope-csrf')
  const first=await api.downloadSearch('alerts',query,signal);expect(first.rows).toBe(1);expect(Array.from(new Uint8Array(await first.blob.arrayBuffer()))).toEqual(Array.from(new TextEncoder().encode(csv)))
  expect(fetcher.mock.calls[0]).toEqual(['/api/alerts/export',{method:'POST',credentials:'same-origin',signal,headers:{'Content-Type':'application/json','X-CSRF-Token':'scope-csrf'},body:JSON.stringify(query)}])
  expect((await api.downloadSearch('context',query)).rows).toBe(1);expect(fetcher.mock.calls[1]?.[0]).toBe('/api/traffic/export')
  expect(instant('2026-10-09T08:00:00.123456789+08:00')).toBe(instant(query.start));expect(instant('invalid')).toBeNull();expect(instant('2026-10-09T99:00:00Z')).toBeNull()
 })
 it('拒绝错误数据集、非精确计数及纳秒范围变化',async()=>{
  const cases:Record<string,string>[]=[{'X-Export-Dataset':'context'},...['01','-1','10001','NaN',''].map(value=>({'X-Export-Rows':value})),{'X-Export-Start':'2026-10-09T00:00:00.123456788Z'},{'X-Export-End':''}]
  for(const headers of cases){
   vi.stubGlobal('fetch',vi.fn().mockResolvedValue(file(csv,headers)))
   await expect(new ApiClient('/api').downloadSearch('alerts',query)).rejects.toMatchObject({code:'invalid_search_export'})
  }
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(file()));await expect(new ApiClient('/api').downloadSearch('alerts',{...query,start:'invalid'})).rejects.toMatchObject({code:'invalid_search_export'})
 })
 it('拒绝类型、预算、长度、摘要和编码异常，不保存部分文件',async()=>{
  const cases:Record<string,string>[]=[{'Content-Type':'application/json'},{'Content-Length':String(8*1024*1024+1)},{'Content-Length':'2'},{'Content-Length':'9999'},{'X-Content-SHA256':''},{'X-Content-SHA256':'0'.repeat(64)}]
  for(const headers of cases){
   vi.stubGlobal('fetch',vi.fn().mockResolvedValue(file(csv,headers)))
   await expect(new ApiClient('/api').downloadSearch('alerts',query)).rejects.toMatchObject({code:'invalid_search_export'})
  }
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(file('invalid_csv')));await expect(new ApiClient('/api').downloadSearch('alerts',query)).rejects.toMatchObject({message:'检索导出文件编码不符合 UTF-8 契约'})
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(file()));vi.stubGlobal('crypto',{});await expect(new ApiClient('/api').downloadSearch('alerts',query)).rejects.toMatchObject({code:'export_verification_unavailable'})
 })
 it('会话变化、取消和授权错误保留准确状态',async()=>{
  const api=new ApiClient('/api'),unauthorized=vi.fn();api.onUnauthorized=unauthorized
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(JSON.stringify({code:'session_expired',message:'会话已失效'}),{status:401})))
  await expect(api.downloadSearch('alerts',query)).rejects.toMatchObject({status:401});expect(unauthorized).toHaveBeenCalledOnce()
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('unavailable',{status:503})));await expect(api.downloadSearch('alerts',query)).rejects.toMatchObject({code:'search_export_failed'})
  vi.stubGlobal('fetch',vi.fn().mockImplementation(()=>{api.setCSRF('changed');return Promise.resolve(file())}));await expect(api.downloadSearch('alerts',query)).rejects.toMatchObject({code:'session_changed'})
  const control=new AbortController();control.abort();vi.stubGlobal('fetch',vi.fn().mockResolvedValue(file()));await expect(api.downloadSearch('alerts',query,control.signal)).rejects.toMatchObject({name:'AbortError'})
 })
})

describe('检索导出弹窗交互',()=>{
 function mountExport(disabled=false){return mount(SearchExportButton,{props:{dataset:'alerts',query:{...query},disabled},global:{plugins:[registerAnt]},attachTo:document.body})}
 function urls(){const create=vi.fn().mockReturnValue('blob:verified_export'),revoke=vi.fn();vi.stubGlobal('URL',{createObjectURL:create,revokeObjectURL:revoke});vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});return {create,revoke}}
 it('使用真实弹窗、遮罩和可访问对话框，内容不会渲染到页面工具栏',async()=>{
  const wrapper=mountExport();await click('导出')
  expect(document.querySelector('a-modal')).toBeNull()
  expect(document.querySelectorAll('.ant-modal')).toHaveLength(1)
  expect(document.querySelectorAll('.ant-modal-mask')).toHaveLength(1)
  const dialog=document.querySelector('[role="dialog"]')!
  expect(dialog).not.toBeNull();expect(dialog.textContent).toContain('导出检索结果')
  expect(wrapper.element.contains(dialog)).toBe(false)
  await click('关闭');expect(document.querySelector('[aria-label="导出筛选条件"]')).toBeNull();wrapper.unmount()
 })
 it('展示已提交的完整筛选与来源条件，并以文本显示载荷样式输入',async()=>{
  const wrapper=mountExport()
  await wrapper.setProps({dataset:'context',query:{...query,keyword:'调查线索',source_ip:'192.0.2.10',destination_ip:'192.0.2.20',method:'GET',path:'/<script>window.exportInjected=true</script>',severity:'high',filter:'http.request.uri contains "admin"',event_kind:'flow',sensor_id:'sensor_owned',sensor_registration_id:'registration_owned',source_generation_id:'generation_owned',flow_id:'18446744073709551615'} as SearchRequest})
  await click('导出')
  const scope=document.querySelector('[aria-label="导出筛选条件"]')!
  for(const text of ['调查线索','源 IP','192.0.2.10','目的 IP','192.0.2.20','HTTP 方法','GET','HTTP 路径','/<script>window.exportInjected=true</script>','严重级别','高','记录类型','会话摘要','探针','sensor_owned','注册代次','registration_owned','来源代次','generation_owned','会话标识','18446744073709551615','高级表达式','http.request.uri contains "admin"'])expect(scope.textContent).toContain(text)
  expect(scope.querySelector('script')).toBeNull();expect(scope.querySelectorAll('dt')).toHaveLength(13)
  await click('关闭');await wrapper.setProps({query:{...query,severity:'unrecognized',event_kind:'unrecognized'} as SearchRequest});await click('导出');expect(document.body.textContent).toContain('unrecognized');wrapper.unmount()
 })
 it('未设置条件时明确时间范围，执行中保持原始条件和原始请求',async()=>{
  const resource=urls(),wrapper=mountExport(),empty={...query,protocol:''}
  await wrapper.setProps({query:empty});await click('导出');expect(document.body.textContent).toContain('未设置其他筛选条件');expect(document.querySelector('[aria-label="导出筛选条件"]')).toBeNull();await click('关闭')
  const original={...query,path:'/submitted'},waiting=deferred<{blob:Blob;rows:number}>();await wrapper.setProps({query:original});await click('导出');download.mockImplementationOnce(()=>waiting.promise);await click('导出CSV')
  await wrapper.setProps({query:{...query,path:'/unsubmitted'}});await flushPromises();const scope=document.querySelector('[aria-label="导出筛选条件"]')!;expect(scope.textContent).toContain('/submitted');expect(scope.textContent).not.toContain('/unsubmitted');expect(download).toHaveBeenCalledWith('alerts',original,expect.any(AbortSignal))
  waiting.resolve({blob:new Blob([csv]),rows:1});await flushPromises();expect(resource.create).toHaveBeenCalledOnce();await click('关闭');wrapper.unmount()
 })
 it('禁用、冻结查询、成功文件与资源清理保持单个弹窗',async()=>{
  const resource=urls(),wrapper=mountExport(true);await click('导出');expect(document.body.textContent).not.toContain('导出检索结果')
  await wrapper.setProps({disabled:false});await click('导出');expect(document.body.textContent).toContain('10,000 条');expect(document.body.textContent).toContain('不含原始载荷')
  download.mockResolvedValueOnce({blob:new NativeBlob([csv]),rows:501});await click('导出CSV');expect(download).toHaveBeenCalledWith('alerts',query,expect.any(AbortSignal));expect(resource.create).toHaveBeenCalledOnce();expect(document.body.textContent).toContain('包含 501 条记录')
  await click('关闭');expect(resource.revoke).toHaveBeenCalledOnce();wrapper.unmount()
 })
 it('错误保留冻结窗口，重复提交和取消不产生迟到下载',async()=>{
  const resource=urls(),wrapper=mountExport();await click('导出');download.mockRejectedValueOnce(new Error('当前范围超出导出上限'));await click('导出CSV');expect(document.body.textContent).toContain('当前范围超出导出上限');expect(resource.create).not.toHaveBeenCalled()
  const waiting=deferred<{blob:Blob;rows:number}>();download.mockImplementationOnce(()=>waiting.promise);await click('导出CSV');expect(button('导出CSV').disabled).toBe(true);const before=download.mock.calls.length;button('导出CSV').click();await flushPromises();expect(download.mock.calls.length).toBe(before)
  const signal=download.mock.lastCall?.[2] as AbortSignal;await click('取消导出');expect(signal.aborted).toBe(true);waiting.resolve({blob:new Blob([csv]),rows:1});await flushPromises();expect(resource.create).not.toHaveBeenCalled();wrapper.unmount()
 })
 it('条件、数据集、身份及卸载变化清理导出状态',async()=>{
  const resource=urls(),wrapper=mountExport();await click('导出');await wrapper.setProps({query:{...query,source_ip:'192.0.2.10'}});await flushPromises();expect(wrapper.getComponent(Modal).props('open')).toBe(false);expect(document.querySelector('[aria-label="导出筛选条件"]')).toBeNull()
  await click('导出');download.mockRejectedValueOnce('unavailable');await click('导出CSV');expect(document.body.textContent).toContain('检索导出未完成，请稍后重试')
  await wrapper.setProps({dataset:'context'});await flushPromises();await click('导出');const waiting=deferred<{blob:Blob;rows:number}>();download.mockImplementationOnce(()=>waiting.promise);await click('导出CSV');const signal=download.mock.lastCall?.[2] as AbortSignal;user.value={...principal,id:'user_other'};await flushPromises();expect(signal.aborted).toBe(true)
  waiting.resolve({blob:new Blob([csv]),rows:1});await flushPromises();expect(resource.create).not.toHaveBeenCalled();await click('导出');const last=deferred<{blob:Blob;rows:number}>();download.mockImplementationOnce(()=>last.promise);await click('导出CSV');const disposed=download.mock.lastCall?.[2] as AbortSignal;wrapper.unmount();expect(disposed.aborted).toBe(true);last.resolve({blob:new Blob([csv]),rows:1});await flushPromises()
 })
})
