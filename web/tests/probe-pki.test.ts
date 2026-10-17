import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {ApiError} from '../packages/shared/src/api'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {createEnrollmentInput,enrollmentError,validEnrollment,validCertificate,validEnrollmentPage,validCertificatePage,type Enrollment,type ProbeCertificate,type EnrollmentDraft} from '../platform/src/features/sensors/pki'
import {useProbePKI} from '../platform/src/features/sensors/useProbePKI'
import {useProbeEnrollment} from '../platform/src/features/sensors/useProbeEnrollment'
import {useProbeRevocation} from '../platform/src/features/sensors/useProbeRevocation'
import {principal,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const user=session.current as ShallowRef<Principal|null>
const now=new Date().toISOString(),later=new Date(Date.now()+3600000).toISOString()
const enrollment:Enrollment={id:'enroll_a',sensor_id:'probe_a',registration_id:'reg_a',created_at:now,expires_at:later,revoked:false,state:'unused'}
const certificate:ProbeCertificate={id:'cert_a',sensor_id:'probe_a',registration_id:'reg_a',fingerprint_sha256:'a'.repeat(64),serial:'1234',not_before:now,not_after:later,state:'issued',ca_revocation:'none',csr_sha256:'b'.repeat(64)}
const draft:EnrollmentDraft={sensor_id:'probe_a',registration_id:'reg_a',name:'办公探针',ttl_seconds:3600}
beforeEach(()=>{user.value=principal;request.mockReset()})
function host<T>(factory:()=>T){let state!:T;const wrapper=mount(defineComponent({setup(){state=factory();return()=>h('div')}}));return {state,wrapper}}

describe('探针证书契约与凭据绑定',()=>{
 it('使用独立随机秘密绑定租户、探针、注册身份及令牌标识',()=>{
  const first=createEnrollmentInput(principal.tenant_id,draft),second=createEnrollmentInput(principal.tenant_id,draft)
  expect(first.token).not.toBe(second.token);const parts=first.token.split('.')
  expect(parts.slice(0,4)).toEqual(['sbe1',principal.tenant_id,draft.sensor_id,draft.registration_id]);expect(parts[4]).toMatch(/^enroll_[a-f0-9]{32}$/);expect(parts[5]).toMatch(/^[A-Za-z0-9_-]{43}$/)
  expect(enrollmentError(draft)).toBe('')
  for(const bad of [{sensor_id:'UPPER'},{registration_id:''},{name:''},{name:' a'},{name:'a\nb'},{name:'a'.repeat(129)},{ttl_seconds:59},{ttl_seconds:86401},{ttl_seconds:1.5}])expect(enrollmentError({...draft,...bad})).not.toBe('')
  expect(()=>createEnrollmentInput('bad/tenant',draft)).toThrow();expect(()=>createEnrollmentInput(principal.tenant_id,{...draft,name:''})).toThrow()
 })
 it('拒绝外域、重复、越界游标、未登记状态和额外证书材料',()=>{
  expect(validEnrollment(enrollment)).toBe(true);expect(validCertificate(certificate)).toBe(true)
  expect(validEnrollmentPage({items:[enrollment],next_cursor:'',ca_configured:true})).toBe(true)
  for(const raw of [null,{}, {...enrollment,id:'../x'},{...enrollment,sensor_id:''},{...enrollment,created_at:'bad'},{...enrollment,expires_at:now},{...enrollment,revoked:1},{...enrollment,state:'success'},{...enrollment,job_id:'bad/id'},{...enrollment,csr_sha256:'bad'}])expect(validEnrollment(raw)).toBe(false)
  for(const raw of [null,{}, {...certificate,state:'active'},{...certificate,id:''},{...certificate,ca_revocation:'ok'},{...certificate,fingerprint_sha256:'bad'},{...certificate,serial:'01'},{...certificate,not_after:now},{...certificate,revoked_at:'bad'},{...certificate,csr_sha256:'bad'},{...certificate,chain_pem:'private-or-public-material'}])expect(validCertificate(raw)).toBe(false)
  for(const page of [{items:[enrollment],next_cursor:'a',ca_configured:true},{items:[enrollment,enrollment],next_cursor:'',ca_configured:true},{items:[enrollment],next_cursor:''},{items:[],next_cursor:1,ca_configured:true}])expect(validEnrollmentPage(page)).toBe(false)
  expect(validCertificatePage({items:[certificate],next_cursor:''},'another_probe')).toBe(false)
  const rows=Array.from({length:20},(_,n)=>({...certificate,id:'cert_'+String(n).padStart(2,'0')}))
  expect(validCertificatePage({items:rows,next_cursor:rows.at(-1)!.id},'probe_a')).toBe(true)
  expect(validCertificatePage({items:[...rows].reverse(),next_cursor:''},'probe_a')).toBe(true)
  expect(validCertificate({...certificate,state:'unknown',fingerprint_sha256:'',serial:''})).toBe(true)
 })
 it('保留数据库对合法标识的排序及原游标',()=>{
  const rows=[{...enrollment,id:'aa'},{...enrollment,id:'a_b'}]
  expect(rows[0]!.id>rows[1]!.id).toBe(true)
  const page={items:rows,next_cursor:'',ca_configured:true}
  expect(validEnrollmentPage(page)).toBe(true)
  expect(page.items.map(row=>row.id)).toEqual(['aa','a_b'])
 })
})

describe('注册目录与提交恢复',()=>{
 it('切换目录取消旧请求，旧证书不能覆盖当前选择，分页范围保持绑定',async()=>{
  const {state,wrapper}=host(useProbePKI)
  request.mockResolvedValueOnce({items:[enrollment],next_cursor:'',ca_configured:true});await state.load();expect(state.enrollments.value.items).toHaveLength(1)
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const loading=state.load();const signal=request.mock.lastCall?.[1].signal as AbortSignal
  request.mockResolvedValueOnce({items:[certificate],next_cursor:''});state.select('certificates','probe_a');await flushPromises();old.resolve({items:[],next_cursor:'',ca_configured:false});await loading
  expect(signal.aborted).toBe(true);expect(state.certificates.value.items).toHaveLength(1)
  request.mockResolvedValueOnce({items:[{...certificate,sensor_id:'foreign'}],next_cursor:''});await state.load();expect(state.error.value).toContain('不一致');expect(state.certificates.value.items).toEqual([])
  state.search('bad/id');await flushPromises();expect(state.error.value).toContain('完整');wrapper.unmount()
  const count=request.mock.calls.length;await state.load();expect(request).toHaveBeenCalledTimes(count)
 })
 it('受限分页、读取错误和登录切换清理旧目录',async()=>{
  const rows=Array.from({length:20},(_,n)=>({...enrollment,id:'enroll_'+String(n).padStart(2,'0')})),{state}=host(useProbePKI)
  request.mockResolvedValueOnce({items:rows,next_cursor:rows.at(-1)!.id,ca_configured:true});await state.load()
  request.mockResolvedValueOnce({items:[],next_cursor:'',ca_configured:true});await state.next();expect(request.mock.lastCall?.[0]).toContain('cursor=enroll_19')
  request.mockResolvedValueOnce({items:[],next_cursor:'',ca_configured:true});await state.previous();await state.previous();expect(state.cursors.value).toEqual([''])
  request.mockRejectedValueOnce(new Error('目录不可用'));await state.load();expect(state.error.value).toBe('目录不可用')
  request.mockResolvedValueOnce({items:[enrollment],next_cursor:'',ca_configured:true});await state.load();user.value={...principal,id:'other_user'};await flushPromises();expect(state.enrollments.value.items).toEqual([])
 })
 it('未知创建结果只重试原令牌和 CSR 绑定信息，明确成功后令牌只保留在窗口内存',async()=>{
  const {state,wrapper}=host(useProbeEnrollment)
  await state.submit({...draft,name:''});expect(request).not.toHaveBeenCalled()
  request.mockRejectedValueOnce(new Error('响应中断'));await state.submit(draft)
  expect(state.unconfirmed.value).toBe(true);expect(state.draft.value).toEqual(draft);const original=request.mock.lastCall?.[1].body
  await state.submit({...draft,name:'另一个名称'});expect(request).toHaveBeenCalledTimes(1)
  request.mockImplementationOnce(async(_path:string,options:{body:{token:string}})=>({...enrollment,id:options.body.token.split('.')[4]}))
  await state.submit();expect(request.mock.lastCall?.[1].body).toEqual(original);expect(state.receipt.value?.sensor_id).toBe(draft.sensor_id);expect(state.token.value).toBe(original.token);expect(state.unconfirmed.value).toBe(false)
  await state.submit(draft);expect(request).toHaveBeenCalledTimes(2)
  wrapper.unmount();expect(state.token.value).toBe('');expect(state.receipt.value).toBeNull()
 })
 it('错误绑定、到期回执、明确拒绝与迟到成功不冒充注册完成',async()=>{
  const {state,wrapper}=host(useProbeEnrollment)
  request.mockResolvedValueOnce(enrollment);await state.submit(draft);expect(state.unconfirmed.value).toBe(true);expect(state.receipt.value).toBeNull()
  request.mockRejectedValueOnce(new ApiError(403,'denied','无注册权限'));await state.submit();expect(state.unconfirmed.value).toBe(false)
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const submitted=state.submit(draft);const input=request.mock.lastCall?.[1].body
  user.value=null;await flushPromises();late.resolve({...enrollment,id:input.token.split('.')[4]});await submitted;expect(state.token.value).toBe('');expect(state.receipt.value).toBeNull()
  wrapper.unmount();await state.submit(draft)
 })
})

describe('证书与令牌撤销结果',()=>{
 it('确认平台拒绝与 CA 状态各自独立，失去登录立即清除原操作',async()=>{
  const {state,wrapper}=host(useProbeRevocation)
  expect(state.choose({kind:'certificate',record:certificate})).toBe(true)
  request.mockRejectedValueOnce(new Error('连接中断'));await state.submit();expect(state.unconfirmed.value).toBe(true)
  expect(state.choose({kind:'enrollment',record:enrollment})).toBe(false)
  request.mockResolvedValueOnce({...certificate,revoked_at:now,ca_revocation:'unknown'});await state.submit()
  expect(state.result.value).toMatchObject({ca_revocation:'unknown',revoked_at:now});expect(request.mock.calls.every(row=>row[0]==='/sensor-certificates/cert_a/revoke')).toBe(true)
  state.reset();state.choose({kind:'enrollment',record:enrollment});request.mockResolvedValueOnce({revoked:true});await state.submit();expect(state.result.value).toBe('revoked')
  user.value=null;await flushPromises();expect(state.target.value).toBeNull();wrapper.unmount()
 })
 it('错指纹、缺少撤销回执及取消后的响应均不能成为成功',async()=>{
  const {state,wrapper}=host(useProbeRevocation);expect(state.choose({kind:'certificate',record:{...certificate,id:''}})).toBe(false)
  state.choose({kind:'certificate',record:certificate});request.mockResolvedValueOnce({...certificate,revoked_at:now,fingerprint_sha256:'f'.repeat(64)});await state.submit();expect(state.unconfirmed.value).toBe(true);expect(state.result.value).toBeNull()
  state.reset();state.choose({kind:'enrollment',record:enrollment});request.mockResolvedValueOnce({revoked:false});await state.submit();expect(state.result.value).toBeNull()
  request.mockRejectedValueOnce(new ApiError(403,'denied','拒绝'));await state.submit();expect(state.unconfirmed.value).toBe(false)
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const work=state.submit();wrapper.unmount();late.resolve({revoked:true});await work;expect(state.result.value).toBeNull()
 })
})
