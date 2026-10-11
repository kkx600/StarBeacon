import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {Form,Modal,message} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {passwordInputError,usePasswordChange,type PasswordInput} from '../platform/src/features/users/usePasswordChange'
import type {UserRecord} from '../platform/src/features/users/user'
import PasswordForm from '../platform/src/features/users/PasswordForm.vue'
import PasswordDialog from '../platform/src/features/users/PasswordDialog.vue'
import UsersWorkspace from '../platform/src/features/users/UsersWorkspace.vue'
import UserDetail from '../platform/src/features/users/UserDetail.vue'
import AppShell from '../packages/shared/src/components/AppShell.vue'
import {principal,deferred,click,button,closedMessage} from './fixtures'

const {request,unauthorized}=vi.hoisted(()=>({request:vi.fn(),unauthorized:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request,onUnauthorized:unauthorized},current:(await import('vue')).shallowRef(null)}}))
const global={plugins:[registerAnt]}
const record:UserRecord={id:'user_owned',username:'值班观察员',role:'viewer',active:true,revision:1,created_at:'2026-10-04T00:00:00Z',updated_at:'2026-10-04T00:00:00Z'}
const self:UserRecord={...record,id:principal.id,username:principal.username,role:'admin'}
const input:PasswordInput={expected_revision:1,current_password:'password-current-owned',new_password:'password-new-owned-1234'}
const changed=(r:UserRecord=record)=>({...r,revision:r.revision+1,updated_at:'2026-10-04T00:01:00Z'})
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();unauthorized.mockReset();request.mockImplementation((path:string,options?:{method?:string})=>Promise.resolve(options?.method==='POST'?changed(path==='/auth/password'?self:record):path==='/auth/account'?self:record));vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(initial:UserRecord|null=record,own=false){let state!:ReturnType<typeof usePasswordChange>;const wrapper=mount(defineComponent({setup(){state=usePasswordChange(initial,own);return()=>h('div')}}));return{state,wrapper}}
async function fill(field:string,value:string){const input=document.getElementById('password-operation_'+field) as HTMLInputElement;input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('密码操作身份与结果核对',()=>{
 it('按 UTF-8 字节验证密码与可写修订，不截断中文密码',()=>{
  expect(passwordInputError(input)).toBe('');expect(passwordInputError({...input,new_password:'中'.repeat(24)})).toBe('')
  for(const value of [0,1.5,1000000])expect(passwordInputError({...input,expected_revision:value})).toContain('修订')
  for(const value of ['', '中'.repeat(25),'old\npassword'])expect(passwordInputError({...input,current_password:value})).toContain('当前登录')
  for(const value of ['short','中'.repeat(25),'new\npassword123'])expect(passwordInputError({...input,new_password:value})).toContain('12～72')
  expect(passwordInputError({...input,new_password:input.current_password})).toContain('相同')
 })
 it('自身账号从专属入口读取，成员重置采用固定目标和修订',async()=>{
  const own=host(null,true);await flushPromises();expect(own.state.record.value).toEqual(self);expect(request).toHaveBeenCalledWith('/auth/account',expect.objectContaining({signal:expect.any(AbortSignal)}));expect(await own.state.save(input)).toEqual(changed(self));expect(request.mock.lastCall?.[0]).toBe('/auth/password')
  const reset=host();expect(await reset.state.save(input)).toEqual(changed());expect(request.mock.lastCall?.[0]).toBe('/users/user_owned/password');expect(request.mock.lastCall?.[1].body).toEqual(input)
 })
 it('账号读取失败和损坏回执保持错误状态，不变为空数据',async()=>{
  const {state}=host();for(const result of [null,{...record,id:'foreign'},{...record,password_hash:'private'}]){request.mockResolvedValueOnce(result);await state.reload();expect(state.error.value).toContain('完整返回')}
  request.mockRejectedValueOnce('offline');await state.reload();expect(state.error.value).toBe('账号信息读取失败');request.mockRejectedValueOnce(new Error('连接失败'));await state.reload();expect(state.error.value).toBe('连接失败');await state.reload();expect(state.record.value).toEqual(record);expect(state.error.value).toBe('')
 })
 it('结果未知冻结原键和密码，人工核对沿用同一请求',async()=>{
  const {state}=host();expect(await state.confirm()).toBeUndefined();request.mockRejectedValueOnce(new Error('网络中断'));await state.save(input);expect(state.unconfirmed.value).toBe(true);const key=request.mock.lastCall?.[1].headers
  await state.reload();expect(request.mock.lastCall?.[1].headers).toEqual(key)
  await state.save({...input,new_password:'different-owned-password'});expect(state.actionError.value).toContain('核对原提交')
  expect(await state.confirm()).toEqual(changed());expect(request.mock.lastCall?.[1].headers).toEqual(key);expect(state.unconfirmed.value).toBe(false)
 })
 it('确定拒绝允许更正输入，408 和非结构化故障维持未知结果',async()=>{
  const {state}=host();for(const status of [400,403,409,410,429]){request.mockRejectedValueOnce(new ApiError(status,'denied','拒绝提交'));await state.save(input);expect(state.unconfirmed.value).toBe(false)}
  request.mockRejectedValueOnce(new ApiError(408,'timeout','结果未知'));await state.save(input);expect(state.unconfirmed.value).toBe(true);request.mockRejectedValueOnce('offline');await state.confirm();expect(state.actionError.value).toContain('尚未确认')
 })
 it('目标、身份、权限、状态、修订与凭据字段必须全部符合回执',async()=>{
  const {state}=host();for(const result of [null,{...changed(),id:'foreign'},{...changed(),username:'other'},{...changed(),role:'admin'},{...changed(),active:false},{...changed(),revision:3},{...changed(),current_password:'private'},{...changed(),new_password:'private'}]){request.mockResolvedValueOnce(result);await state.save(input);expect(state.unconfirmed.value).toBe(true)}
  expect(await state.confirm()).toEqual(changed());expect(state.unconfirmed.value).toBe(false)
 })
 it('本地不合法输入和无账号状态不会创建请求',async()=>{
  const {state}=host();expect(await state.save({...input,new_password:'short'})).toBeUndefined();expect(request).not.toHaveBeenCalled();expect(state.actionError.value).toContain('12～72')
  const read=deferred<unknown>();request.mockReturnValueOnce(read.promise);const pending=state.reload();expect(await state.save(input)).toBeUndefined();read.resolve(record);await pending
 })
 it('迟到读取和写入不能覆盖新请求或已结束的身份',async()=>{
  const {state,wrapper}=host();const read=deferred<unknown>();request.mockReturnValueOnce(read.promise);const first=state.reload();await state.reload();read.resolve({...record,revision:5});await first;expect(state.record.value?.revision).toBe(1)
  const write=deferred<unknown>();request.mockReturnValueOnce(write.promise);const pending=state.save(input);expect(await state.save(input)).toBeUndefined();await state.reload();const signal=request.mock.lastCall?.[1].signal as AbortSignal;(session.current as ShallowRef<Principal|null>).value={...principal,id:'other'};await flushPromises();expect(signal.aborted).toBe(true);write.resolve(changed());await pending;expect(state.record.value).toBeNull();expect(state.unconfirmed.value).toBe(false);expect(await state.save(input)).toBeUndefined();await state.reload();wrapper.unmount()
 })
 it('超时保持原请求，关闭窗口会终止读取和清除待核对密码',async()=>{
  vi.useFakeTimers();const {state,wrapper}=host();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const pending=state.save(input);await vi.advanceTimersByTimeAsync(30000);late.resolve(changed());await pending;expect(state.unconfirmed.value).toBe(true);expect(state.actionError.value).toContain('尚未确认');wrapper.unmount();expect(state.record.value).toBeNull();expect(await state.confirm()).toBeUndefined()
  const after=host();const reading=deferred<unknown>();request.mockReturnValueOnce(reading.promise);const read=after.state.reload();const signal=request.mock.lastCall?.[1].signal as AbortSignal;after.wrapper.unmount();expect(signal.aborted).toBe(true);reading.reject(new Error('late'));await read;expect(after.state.record.value).toBeNull()
 })
 it('组件销毁后的写入结果不产生成功回执',async()=>{
  const {state,wrapper}=host();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const pending=state.save(input);wrapper.unmount();late.resolve(changed());expect(await pending).toBeUndefined();expect(state.record.value).toBeNull()
 })
})

describe('密码表单与真实 Ant 交互',()=>{
 it('空值、中文边界及两次密码不一致定位错误，合法提交不输出确认密码',async()=>{
  const w=mount(PasswordForm,{props:{record,own:false,busy:false,unconfirmed:false,error:''},global,attachTo:document.body});await flushPromises();await click('重置密码');expect(w.emitted('save')).toBeUndefined();expect(document.activeElement?.getAttribute('aria-label')).toBe('密码表单校验信息')
  await fill('currentPassword',input.current_password);await fill('newPassword','中'.repeat(25));await fill('confirmation','中'.repeat(25));await click('重置密码');expect(document.body.textContent).toContain('12～72');await fill('newPassword',input.new_password);await fill('confirmation','different');await click('重置密码');expect(document.body.textContent).toContain('不一致');await fill('confirmation',input.new_password);await click('重置密码');expect(w.emitted('save')?.[0]?.[0]).toEqual(input)
  expect((document.getElementById('password-operation_currentPassword') as HTMLInputElement).type).toBe('password');expect(document.querySelectorAll('label[for^="password-operation_"]').length).toBe(3);await click('刷新账号');expect(w.emitted('reload')).toHaveLength(1)
 })
 it('提交期间无法重复写入，结果未知的确认按钮可操作',async()=>{
  const w=mount(PasswordForm,{props:{record:self,own:true,busy:true,unconfirmed:false,error:''},global,attachTo:document.body});await flushPromises();expect(button('修改密码').disabled).toBe(true);w.getComponent(Form).vm.$emit('finish');expect(w.emitted('save')).toBeUndefined();await w.setProps({busy:false,unconfirmed:true,error:'结果尚未确认'});await flushPromises();expect((document.getElementById('password-operation_newPassword') as HTMLInputElement).disabled).toBe(true);expect(button('核对原提交').disabled).toBe(false);await click('核对原提交');expect(w.emitted('confirm')).toHaveLength(1);expect(document.body.textContent).toContain('重新登录核对')
 })
 it('重置使用独立弹窗，成功后角色与状态可见且只发一次事件',async()=>{
  const w=mount(PasswordDialog,{props:{record,own:false},global,attachTo:document.body});await flushPromises();w.getComponent(PasswordForm).vm.$emit('save',input);await flushPromises();expect(w.emitted('changed')).toHaveLength(1);expect(w.emitted('close')).toHaveLength(1);expect(unauthorized).not.toHaveBeenCalled();w.getComponent(Modal).vm.$emit('cancel');expect(w.emitted('close')).toHaveLength(2)
 })
 it('自身修改成功清除平台会话，受理失败保留编辑及原提交核对',async()=>{
  const w=mount(PasswordDialog,{props:{own:true},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain(self.username);const pending=deferred<unknown>();request.mockReturnValueOnce(pending.promise);w.getComponent(PasswordForm).vm.$emit('save',input);await flushPromises();expect(w.getComponent(Modal).props('closable')).toBe(false);pending.resolve(changed(self));await flushPromises();expect(unauthorized).toHaveBeenCalledTimes(1);expect(w.emitted('changed')).toHaveLength(1);w.unmount()
  const reset=mount(PasswordDialog,{props:{record,own:false},global,attachTo:document.body});await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));reset.getComponent(PasswordForm).vm.$emit('save',input);await flushPromises();expect(reset.emitted('changed')).toBeUndefined();reset.getComponent(PasswordForm).vm.$emit('confirm');await flushPromises();expect(reset.emitted('changed')).toHaveLength(1)
 })
 it('账号加载失败提供重试入口，读取失败不会出现密码提交表单',async()=>{
  request.mockRejectedValueOnce(new Error('账号读取失败'));const w=mount(PasswordDialog,{props:{own:true},global,attachTo:document.body});await flushPromises();expect(w.findComponent(PasswordForm).exists()).toBe(false);await click('重试');expect(w.findComponent(PasswordForm).exists()).toBe(true)
 })
 it('用户详情到密码弹窗保持单表布局，重置与权限编辑分开',async()=>{
  request.mockImplementation((path:string,options?:{method?:string})=>Promise.resolve(options?.method==='POST'?changed():path.startsWith('/users?')?{items:[record],next_cursor:''}:record));const w=mount(UsersWorkspace,{global,attachTo:document.body});await flushPromises();await click('查看');expect(w.findComponent(UserDetail).exists()).toBe(true);await click('重置密码');expect(w.findComponent(UserDetail).exists()).toBe(false);expect(w.findAll('table').length).toBe(1);expect(w.getComponent(PasswordDialog).props('own')).toBe(false);w.getComponent(PasswordDialog).vm.$emit('changed');await flushPromises();w.getComponent(PasswordDialog).vm.$emit('close');await flushPromises();expect(w.findComponent(PasswordDialog).exists()).toBe(false)
 })
 it('平台顶栏提供账号入口，采集器不会展示未实现的密码功能',async()=>{
  const w=mount(AppShell,{props:{title:'态势感知系统',username:principal.username,current:'/users',items:[],allowPasswordChange:true},global,attachTo:document.body});await flushPromises();await click('修改密码');expect(w.emitted('password')).toHaveLength(1);await w.setProps({allowPasswordChange:false});expect(w.text()).not.toContain('修改密码')
 })
})
