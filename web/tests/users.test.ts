import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {Select,Modal,Form,message} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {useUsers} from '../platform/src/features/users/useUsers'
import {validUsername,userInputError,validUserRecord,validUserPage,type UserCreate,type UserRecord} from '../platform/src/features/users/user'
import UserForm from '../platform/src/features/users/UserForm.vue'
import UserDetail from '../platform/src/features/users/UserDetail.vue'
import UsersWorkspace from '../platform/src/features/users/UsersWorkspace.vue'
import {principal,deferred,click,button,closedMessage} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const global={plugins:[registerAnt]},clone=<T,>(value:T):T=>structuredClone(value)
const input:UserCreate={username:'值班观察员',password:'owned-password-1234',role:'viewer',active:true}
const record:UserRecord={id:'user_owned',username:input.username,role:'viewer',active:true,revision:1,created_at:'2026-10-03T12:00:00Z',updated_at:'2026-10-03T12:00:00Z'}
const self:UserRecord={...record,id:principal.id,username:'admin',role:'admin'}
const change={expected_revision:1,role:'admin' as const,active:false}
const changed={...record,role:'admin' as const,active:false,revision:2,updated_at:'2026-10-03T12:01:00Z'}
const page={items:[record,self],next_cursor:''}
function answer(path:string,options?:{method?:string;body?:unknown}){return Promise.resolve(options?.method==='POST'?record:options?.method==='PATCH'?changed:path.startsWith('/users?')?page:path.endsWith('/'+self.id)?self:record)}
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();request.mockImplementation(answer);vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(){let state!:ReturnType<typeof useUsers>;const wrapper=mount(defineComponent({setup(){state=useUsers();return()=>h('div')}}));return{state,wrapper}}
const formProps={record:null,busy:false,unconfirmed:false,error:'',selfId:principal.id}
async function form(props:Record<string,unknown>={}){const w=mount(UserForm,{props:{...formProps,...props},global,attachTo:document.body});await flushPromises();return w}
async function fill(id:string,value:string){const element=document.getElementById(id) as HTMLInputElement;element.value=value;element.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('租户用户数据与凭据边界',()=>{
 it('账号和密码按 UTF-8 字节验证，修订与状态必须明确',()=>{
  expect(userInputError(input)).toBe('');expect(validUsername('中文账号')).toBe(true)
  for(const name of ['', 'ab',' leading','trailing ','hidden\u200dname','null\u0000name','中'.repeat(22)])expect(validUsername(name)).toBe(false)
  for(const bad of [{...input,role:'owner'},{...input,active:null},{...input,username:'a'},{...input,password:'short'},{...input,password:'中'.repeat(25)},{...input,password:'control\npassword'},{...input,password:null}])expect(userInputError(bad as any)).not.toBe('')
  expect(userInputError({...input,password:'中'.repeat(24)})).toBe('');expect(userInputError({...input,password:'a'.repeat(12)})).toBe('')
  expect(userInputError(change)).toBe('');for(const revision of [0,1.5,1000000])expect(userInputError({...change,expected_revision:revision})).not.toBe('')
 })
 it('完整公共记录拒绝密码字段、重复身份、异常顺序与损坏续点',()=>{
  expect(validUserRecord(record)).toBe(true);expect(validUserPage(page)).toBe(true)
  for(const bad of [null,[],{...record,id:'bad/id'},{...record,username:' x'},{...record,role:'owner'},{...record,active:null},{...record,revision:0},{...record,revision:1000001},{...record,created_at:'bad'},{...record,updated_at:'bad'},{...record,updated_at:'2025-01-01'},{...record,password:'private'},{...record,password_hash:'private'}])expect(validUserRecord(bad)).toBe(false)
  for(const bad of [null,{items:null,next_cursor:''},{items:[record,record],next_cursor:''},{items:[self,record],next_cursor:''},{items:[record],next_cursor:'bad/id'},{items:[{...record,role:'owner'}],next_cursor:''}])expect(validUserPage(bad)).toBe(false)
  const rows=Array.from({length:20},(_,i)=>({...record,id:'user_'+String(99-i).padStart(2,'0')}));expect(validUserPage({items:rows,next_cursor:rows[19]!.id})).toBe(true);expect(validUserPage({items:[...rows,record],next_cursor:''})).toBe(false)
 })
})

describe('用户管理请求与结果确认',()=>{
 it('筛选和分页只采用最新列表，失败有恢复入口',async()=>{
  const {state}=host();await flushPromises();state.previous();state.next();expect(state.page.value).toEqual(page)
  const rows=Array.from({length:20},(_,i)=>({...record,id:'user_'+String(99-i).padStart(2,'0')}));request.mockResolvedValueOnce({items:rows,next_cursor:rows[19]!.id});await state.refresh();state.next();await flushPromises();expect(state.cursors.value).toHaveLength(2);expect(request.mock.lastCall?.[0]).toContain('before=user_80');state.previous();await flushPromises();expect(state.cursors.value).toEqual(['']);state.search('admin','false');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('role=admin&active=false')
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const reading=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal;await state.refresh();old.resolve({items:[],next_cursor:''});await reading;expect(signal.aborted).toBe(true);expect(state.page.value.items).toHaveLength(2)
  request.mockResolvedValueOnce({items:[],next_cursor:'foreign'});await state.refresh();expect(state.error.value).toContain('完整返回');request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('用户列表读取失败');await state.refresh();expect(state.error.value).toBe('')
 })
 it('详情身份和迟到响应受校验，关闭与卸载取消读取',async()=>{
  const {state,wrapper}=host();await flushPromises();await state.reloadDetail();await state.select(record.id);expect(state.selected.value).toEqual(record)
  request.mockResolvedValueOnce(self);await state.reloadDetail();expect(state.detailError.value).toContain('完整返回');request.mockRejectedValueOnce('offline');await state.reloadDetail();expect(state.detailError.value).toBe('用户详情读取失败');await state.reloadDetail();expect(state.detailError.value).toBe('')
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const read=state.select(record.id);state.clearSelection();late.resolve(record);await read;expect(state.selected.value).toBeNull()
  const closed=deferred<unknown>();request.mockReturnValueOnce(closed.promise);const out=state.select(record.id);wrapper.unmount();closed.resolve(record);await out;await state.select(record.id);await state.refresh();state.search('','');expect(state.selected.value).toBeNull();expect(await state.save('',input)).toBeUndefined()
 })
 it('创建结果未知时冻结原输入与键，精确确认避免重复账号',async()=>{
  const {state}=host();await flushPromises();expect(await state.confirm()).toBeUndefined();request.mockRejectedValueOnce(new Error('网络中断'));await state.save('',input);expect(state.unconfirmed.value).toBe(true);const key=request.mock.lastCall?.[1].headers
  const draft=state.pendingInput()!;(draft.input as UserCreate).password='changed';expect((state.pendingInput()!.input as UserCreate).password).toBe(input.password)
  await state.save('',{...input,role:'admin'});expect(state.actionError.value).toContain('核对原提交');state.clearActionError();expect(state.actionError.value).not.toBe('')
  expect(await state.confirm()).toEqual(record);await flushPromises();expect(state.unconfirmed.value).toBe(false);expect(request.mock.calls.filter(c=>c[1]?.method==='POST').map(c=>c[1].headers)).toEqual([key,key]);expect(state.pendingInput()).toBeUndefined()
 })
 it('角色与停用回执必须匹配目标、修订和状态，凭据不能回显',async()=>{
  const {state}=host();await flushPromises()
  for(const result of [{...changed,id:'foreign'},{...changed,revision:3},{...changed,active:true},{...changed,role:'viewer'},{...changed,password_hash:'private'}]){request.mockResolvedValueOnce(result);await state.save(record.id,change);expect(state.unconfirmed.value).toBe(true)}
  request.mockResolvedValueOnce(changed);expect(await state.confirm()).toEqual(changed);await flushPromises()
  request.mockResolvedValueOnce({...record,username:'foreign'});await state.save('',input);expect(state.unconfirmed.value).toBe(true);expect(state.actionError.value).toContain('回执')
 })
 it('确定拒绝释放原请求，超时与非结构化失败仍待确认',async()=>{
  const {state}=host();await flushPromises()
  for(const status of [400,403,409,410,429]){request.mockRejectedValueOnce(new ApiError(status,'rejected','请求被拒绝'));await state.save('',input);expect(state.unconfirmed.value).toBe(false);state.clearActionError();expect(state.actionError.value).toBe('')}
  request.mockRejectedValueOnce(new ApiError(408,'timeout','结果未知'));await state.save('',input);expect(state.unconfirmed.value).toBe(true);request.mockRejectedValueOnce('offline');await state.confirm();expect(state.actionError.value).toContain('尚未确认')
 })
 it('写入超时不采用迟到回执，当前身份变化清除内存中的原密码',async()=>{
  vi.useFakeTimers();const {state,wrapper}=host();await flushPromises();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const writing=state.save('',input);expect(await state.save('',input)).toBeUndefined();await vi.advanceTimersByTimeAsync(30000);late.resolve(record);await writing;expect(state.unconfirmed.value).toBe(true);expect(state.actionError.value).toContain('尚未确认');await state.confirm();await flushPromises();expect(state.unconfirmed.value).toBe(false)
  const stale=deferred<unknown>();request.mockReturnValueOnce(stale.promise);const out=state.save('',input);const signal=request.mock.lastCall?.[1].signal as AbortSignal;(session.current as ShallowRef<Principal|null>).value={...principal,id:'u_other'};await flushPromises();expect(signal.aborted).toBe(true);expect(state.pendingInput()).toBeUndefined();stale.resolve(record);await out;expect(state.selected.value).toBeNull()
  const stopped=deferred<unknown>();request.mockReturnValueOnce(stopped.promise);const last=state.save('',input);wrapper.unmount();stopped.resolve(record);await last;expect(state.pendingInput()).toBeUndefined()
 })
})

describe('用户管理页面与表单交互',()=>{
 it('空值与中文密码边界会定位错误，合法创建包含明确角色与状态',async()=>{
  const w=await form();await click('创建用户');expect(w.emitted('save')).toBeUndefined();expect(document.activeElement?.getAttribute('aria-label')).toBe('用户表单校验信息');await fill('user-name',input.username);await fill('user-password','中'.repeat(25));await click('创建用户');expect(document.body.textContent).toContain('12～72');await fill('user-password',input.password);await click('创建用户');expect(w.emitted('save')?.[0]?.[0]).toEqual(input);expect((document.getElementById('user-password') as HTMLInputElement).type).toBe('password');await click('关闭');expect(w.emitted('close')).toHaveLength(1)
 })
 it('编辑没有密码入口，无变化不能提交，停用明确撤销既有会话',async()=>{
  const w=await form({record});expect(document.getElementById('user-password')).toBeNull();expect((document.getElementById('user-name') as HTMLInputElement).readOnly).toBe(true);await click('提交变更');expect(document.body.textContent).toContain('没有可提交');await w.findAllComponents(Select)[0]!.setValue('admin','value');await w.findAllComponents(Select)[1]!.setValue('false','value');await click('提交变更');expect(w.emitted('save')?.[0]?.[0]).toEqual(change);expect(document.body.textContent).toContain('既有会话失效')
 })
 it('Escape 收起菜单、未知结果冻结字段、错误信息和确认入口可操作',async()=>{
  const w=await form({draft:input});const role=w.findAllComponents(Select)[0]!;await role.find('.ant-select-selector').trigger('mousedown');await flushPromises();const escape=new KeyboardEvent('keydown',{key:'Escape',keyCode:27,bubbles:true});Object.defineProperty(escape,'which',{value:27});role.find('input').element.dispatchEvent(escape);await flushPromises();expect(w.emitted('close')).toBeUndefined();expect(role.find('input').attributes('aria-expanded')).toBe('false')
  await w.setProps({unconfirmed:true,error:'提交结果尚未确认'});await flushPromises();expect((document.getElementById('user-name') as HTMLInputElement).disabled).toBe(true);expect(document.activeElement?.getAttribute('aria-label')).toBe('用户表单校验信息');await click('核对原提交');expect(w.emitted('confirm')).toHaveLength(1);await w.setProps({busy:true});expect(w.getComponent(Modal).props('closable')).toBe(false)
 })
 it('当前登录用户受保护，详情仅展示公开数据且提供真实恢复入口',async()=>{
  const w=await form({record:self});expect(button('提交变更').disabled).toBe(true);w.getComponent(Form).vm.$emit('finish');await flushPromises();expect(w.emitted('save')).toBeUndefined();w.unmount()
  const d=mount(UserDetail,{props:{record:self,pending:false,error:'',selfId:principal.id},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain('当前登录账号受保护');expect(button('编辑用户').disabled).toBe(true);await d.setProps({record});await click('编辑用户');expect(d.emitted('edit')).toHaveLength(1);await d.setProps({record:null,error:'用户服务暂不可用'});await click('重试');expect(d.emitted('reload')).toHaveLength(1);await d.getComponent(Modal).vm.$emit('cancel');expect(d.emitted('close')).toHaveLength(1)
 })
 it('独立单表页面支持详情、编辑、创建、筛选与恢复原提交',async()=>{
  const w=mount(UsersWorkspace,{global,attachTo:document.body});await flushPromises();expect(w.findAll('table').length).toBe(1);expect(w.text()).toContain('用户管理');expect(button('上一页').disabled).toBe(true);await click('查询');await click('重置');await click('刷新');await click('查看');expect(document.body.textContent).toContain('用户详情');await click('编辑用户');expect(document.body.textContent).toContain('编辑用户');const f=w.getComponent(UserForm);f.vm.$emit('save',change);await flushPromises();expect(request.mock.calls.some(c=>c[1]?.method==='PATCH')).toBe(true);expect(document.body.textContent).toContain('用户详情');await w.getComponent(UserDetail).vm.$emit('close');await flushPromises()
  await click('创建用户');request.mockRejectedValueOnce(new Error('连接中断'));w.getComponent(UserForm).vm.$emit('save',input);await flushPromises();expect(document.body.textContent).toContain('字段已锁定');w.getComponent(UserForm).vm.$emit('close');await flushPromises();await click('核对原提交');expect((document.getElementById('user-name') as HTMLInputElement).value).toBe(input.username);w.getComponent(UserForm).vm.$emit('confirm');await flushPromises();expect(document.body.textContent).toContain('用户详情');await w.getComponent(UserDetail).vm.$emit('reload');await flushPromises()
 })
})
