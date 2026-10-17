import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {Modal} from 'ant-design-vue'
import type {ShallowRef} from 'vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import EnrollmentForm from '../platform/src/features/sensors/EnrollmentForm.vue'
import PKIDetail from '../platform/src/features/sensors/PKIDetail.vue'
import PKITable from '../platform/src/features/sensors/PKITable.vue'
import PKIRevocationDialog from '../platform/src/features/sensors/PKIRevocationDialog.vue'
import ProbePKIWorkspace from '../platform/src/features/sensors/ProbePKIWorkspace.vue'
import ProbeIdentitySummary from '../packages/shared/src/components/ProbeIdentitySummary.vue'
import type {Enrollment,ProbeCertificate} from '../platform/src/features/sensors/pki'
import {principal,click} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const user=session.current as ShallowRef<Principal|null>
const now=new Date().toISOString(),later=new Date(Date.now()+3600000).toISOString()
const enrollment:Enrollment={id:'enroll_a',sensor_id:'probe_a',registration_id:'reg_a',created_at:now,expires_at:later,revoked:false,state:'unused'}
const certificate:ProbeCertificate={id:'cert_a',sensor_id:'probe_a',registration_id:'reg_a',fingerprint_sha256:'a'.repeat(64),serial:'1234',not_before:now,not_after:later,state:'issued',ca_revocation:'none',csr_sha256:'b'.repeat(64)}
const formProps={busy:false,locked:false,error:'',receipt:null,token:''}
const global={plugins:[registerAnt]}
beforeEach(()=>{user.value=principal;request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/sensors/')?{items:[certificate],next_cursor:''}:{items:[enrollment],next_cursor:'',ca_configured:true}))})
async function input(label:string,value:string){const element=document.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;element.value=value;element.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('探针注册表单及只读详情',()=>{
 it('校验后提交固定注册身份，未确认时仅允许核对原请求',async()=>{
  const wrapper=mount(EnrollmentForm,{props:formProps,global,attachTo:document.body})
  await click('创建注册凭据');expect(document.body.textContent).toContain('探针名称')
  await input('探针名称','办公探针');await input('探针标识','probe_a');await click('创建注册凭据')
  expect(wrapper.emitted('save')?.[0]?.[0]).toMatchObject({name:'办公探针',sensor_id:'probe_a',ttl_seconds:3600,registration_id:expect.stringMatching(/^reg_[a-f0-9]{32}$/)})
  expect(document.querySelector('.ant-modal-footer')?.textContent).toContain('创建注册凭据')
  await wrapper.setProps({locked:true,error:'原提交尚未确认'});expect(document.querySelector<HTMLInputElement>('input[aria-label="探针名称"]')?.disabled).toBe(true)
  await click('核对原提交');expect(wrapper.emitted('confirm')).toHaveLength(1)
  await wrapper.setProps({busy:true});document.querySelector('form')?.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));await flushPromises();expect(wrapper.emitted('save')).toHaveLength(1)
  await wrapper.setProps({busy:false});await click('关闭');expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('令牌仅在成功窗口提供，失效凭据不可下载，关闭不暴露目录中的秘密',async()=>{
  const wrapper=mount(EnrollmentForm,{props:{...formProps,receipt:enrollment,token:'synthetic-token-for-download'},global,attachTo:document.body})
  expect(document.querySelector<HTMLInputElement>('input[aria-label="一次性注册令牌"]')?.type).toBe('password')
  const create=vi.fn().mockReturnValue('blob:synthetic-pki');Object.defineProperty(URL,'createObjectURL',{value:create,configurable:true});Object.defineProperty(URL,'revokeObjectURL',{value:vi.fn(),configurable:true})
  const anchor=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{})
  await click('保存令牌文件');expect(create).toHaveBeenCalledOnce();expect(anchor).toHaveBeenCalledOnce()
  await wrapper.setProps({receipt:{...enrollment,revoked:true}});await click('保存令牌文件');expect(document.body.textContent).toContain('注册凭据已不可用');expect(create).toHaveBeenCalledOnce()
  await wrapper.setProps({receipt:enrollment});create.mockImplementation(()=>{throw new Error('下载被拒绝')});await click('保存令牌文件');expect(document.body.textContent).toContain('文件保存未完成')
  await click('关闭窗口');expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('目录按单表切换，展示未知签发与吊销状态，只有可操作记录提供撤销入口',async()=>{
  const wrapper=mount(PKITable,{props:{mode:'enrollments',enrollments:[enrollment],certificates:[],locked:false},global})
  expect(wrapper.findAll('.ant-table')).toHaveLength(1);await click('查看',wrapper.element);expect(wrapper.emitted('view')?.[0]).toEqual([enrollment]);await click('查看证书',wrapper.element);expect(wrapper.emitted('certificates')?.[0]).toEqual(['probe_a']);await click('撤销令牌',wrapper.element);expect(wrapper.emitted('revoke')?.[0]).toEqual([enrollment])
  await wrapper.setProps({mode:'certificates',enrollments:[],certificates:[{...certificate,revoked_at:now,ca_revocation:'unknown'}]});expect(wrapper.text()).toContain('平台已吊销');expect(wrapper.text()).toContain('待核实');await click('重试CA吊销',wrapper.element)
  await wrapper.setProps({certificates:[{...certificate,state:'unknown',fingerprint_sha256:'',serial:''}]});expect(wrapper.text()).toContain('尚未取得签发回执');expect(wrapper.findAll('button').some(b=>b.text()==='吊销')).toBe(false)
  await wrapper.setProps({mode:'enrollments',enrollments:[{...enrollment,revoked:true,state:'revoked'}]});expect(wrapper.text()).not.toContain('撤销令牌')
 })
 it('详情展示原始绑定和 CSR 摘要，不把未签发时间显示成有效证书',async()=>{
  const wrapper=mount(PKIDetail,{props:{record:enrollment},global,attachTo:document.body});expect(document.body.textContent).toContain('注册截止时间');expect(document.body.textContent).toContain('尚未提交 CSR')
  await wrapper.setProps({record:{...certificate,state:'unknown',fingerprint_sha256:'',serial:''}});expect(document.body.textContent).toContain('尚未取得签发回执');expect(document.body.textContent).toContain(certificate.csr_sha256)
  await wrapper.setProps({record:{...certificate,revoked_at:now,ca_revocation:'confirmed'}});expect(document.body.textContent).toContain('已确认');expect(document.body.textContent).toContain(certificate.fingerprint_sha256)
  wrapper.getComponent(Modal).vm.$emit('cancel');expect(wrapper.emitted('close')).toHaveLength(1)
 })
})
describe('探针证书管理工作区',()=>{
 it('切换登录身份关闭旧租户详情和表单，不保留目标探针',async()=>{
  const wrapper=mount(ProbePKIWorkspace,{props:{sensorId:'probe_a'},global,attachTo:document.body});await flushPromises();await click('查看');expect(wrapper.getComponent(PKIDetail).props('record')).not.toBeNull()
  user.value={...principal,id:'another_admin',tenant_id:'another_tenant'};await flushPromises();expect(wrapper.getComponent(PKIDetail).props('record')).toBeNull();expect(request.mock.lastCall?.[0]).toBe('/sensor-enrollments')
  await click('创建注册凭据');expect(document.querySelector('input[aria-label="探针名称"]')).not.toBeNull();user.value=null;await flushPromises();expect(document.querySelector('input[aria-label="探针名称"]')).toBeNull()
 })
 it('令牌与证书目录分别呈现，详情及吊销均使用弹窗，CA 未配置禁用创建',async()=>{
  const wrapper=mount(ProbePKIWorkspace,{global,attachTo:document.body});await flushPromises();expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  await click('查看');expect(document.body.textContent).toContain('探针注册凭据详情');wrapper.getComponent(PKIDetail).vm.$emit('close');await flushPromises()
  await click('查看证书');expect(request.mock.lastCall?.[0]).toBe('/sensors/probe_a/certificates');await flushPromises();expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  await click('吊销');expect(document.body.textContent).toContain('吊销探针证书');request.mockResolvedValueOnce({...certificate,revoked_at:now,ca_revocation:'unknown'});await click('吊销证书');expect(document.body.textContent).toContain('平台已拒绝此证书；CA 吊销尚未取得可核实确认');await click('关闭')
  request.mockResolvedValueOnce({items:[],next_cursor:'',ca_configured:false});await click('注册凭据');expect(document.body.textContent).toContain('独立 CA 尚未配置');expect(Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find(b=>b.textContent?.replace(/\s/g,'')==='创建注册凭据')?.disabled).toBe(true)
 })
 it('关闭未确认表单仍可恢复原提交，成功后关闭清除令牌，指定探针直接查询目录',async()=>{
  const wrapper=mount(ProbePKIWorkspace,{global,attachTo:document.body});await flushPromises();await click('创建注册凭据');await input('探针名称','办公探针');await input('探针标识','probe_a')
  request.mockRejectedValueOnce(new Error('连接中断'));await click('创建注册凭据',document.querySelector('.ant-modal-footer')!);expect(document.body.textContent).toContain('核对原提交');await click('关闭');expect(document.body.textContent).toContain('核对注册提交')
  await click('核对注册提交');expect(document.querySelector<HTMLInputElement>('input[aria-label="探针名称"]')?.value).toBe('办公探针')
  request.mockImplementationOnce(async(_path:string,options:{body:{token:string}})=>{const parts=options.body.token.split('.');return{...enrollment,id:parts[4],sensor_id:parts[2],registration_id:parts[3]}})
  await click('核对原提交');expect(document.body.textContent).toContain('保存令牌文件');await click('关闭窗口');expect(document.querySelector('input[aria-label="一次性注册令牌"]')).toBeNull()
  await wrapper.setProps({sensorId:'probe_a'});await flushPromises();expect(request.mock.lastCall?.[0]).toBe('/sensors/probe_a/certificates')
  await wrapper.setProps({sensorId:undefined});await flushPromises();expect(request.mock.lastCall?.[0]).toBe('/sensor-enrollments')
 })
 it('撤销令牌与证书采用独立提示，未知操作保持原对象',async()=>{
  const wrapper=mount(PKIRevocationDialog,{props:{target:{kind:'enrollment',record:enrollment},busy:false,locked:true,error:'连接中断',result:null},global,attachTo:document.body});expect(document.body.textContent).toContain('已签发证书保持独立');await click('核对原操作');expect(wrapper.emitted('submit')).toHaveLength(1)
  await wrapper.setProps({result:'revoked'});expect(document.body.textContent).toContain('注册令牌已撤销')
  await wrapper.setProps({target:{kind:'certificate',record:certificate},result:{...certificate,revoked_at:now,ca_revocation:'confirmed'}});expect(document.body.textContent).toContain('CA 已确认吊销');await click('关闭');expect(wrapper.emitted('close')).toHaveLength(1)
 })
})
describe('本机证书展示',()=>{
 it('清楚区分静态、未生效、有效、续签窗口和到期，不提供密钥操作',async()=>{
  const identity={mode:'managed' as const,sensor_id:'probe_a',registration_id:'reg_a',fingerprint_sha256:'a'.repeat(64),not_before:'2026-10-17T00:00:00Z',renew_after:'2026-10-17T02:00:00Z',not_after:'2026-10-17T03:00:00Z'}
  const wrapper=mount(ProbeIdentitySummary,{props:{identity,now:Date.parse('2026-10-17T01:00:00Z')},global})
  expect(wrapper.text()).toContain('证书有效');await wrapper.setProps({now:Date.parse('2026-10-17T02:00:00Z')});expect(wrapper.text()).toContain('续签窗口');await wrapper.setProps({now:Date.parse('2026-10-17T03:00:00Z')});expect(wrapper.text()).toContain('证书已到期');await wrapper.setProps({now:Date.parse('2026-10-16T23:00:00Z')});expect(wrapper.text()).toContain('证书尚未生效');await wrapper.setProps({identity:{...identity,mode:'static'}});expect(wrapper.text()).toContain('不参与自动续签');expect(wrapper.findAll('button')).toHaveLength(0)
 })
})
