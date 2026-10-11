import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {h,type ShallowRef} from 'vue'
import {Menu} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {palette,appTheme,applyPalette} from '../packages/shared/src/theme'
import {formatBytes,formatBitRate,formatQuantity,compareQuantity} from '../packages/shared/src/utils/format'
import {safeReturnPath,migrateLegacyHash} from '../packages/shared/src/utils/history'
import {formatTime,formatPercent,formatHealthErrors,type Principal} from '../packages/shared/src/types'
import AppShell from '../packages/shared/src/components/AppShell.vue'
import {principal,click} from './fixtures'
const {request,restore,login,logout}=vi.hoisted(()=>({request:vi.fn(),restore:vi.fn(),login:vi.fn(),logout:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null),pending:(await import('vue')).shallowRef(false),error:(await import('vue')).shallowRef(''),restore,login,logout}}))
vi.mock('../collector/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null),pending:(await import('vue')).shallowRef(false),error:(await import('vue')).shallowRef(''),restore,login,logout}}))
beforeEach(()=>{request.mockReset();restore.mockReset();restore.mockResolvedValue(undefined);login.mockReset();login.mockResolvedValue(false);logout.mockReset();logout.mockResolvedValue(undefined);request.mockImplementation((path:string)=>Promise.resolve(path==='/alerts/search'?{items:[],total:0,page:1,page_size:20}:path==='/health'?{errors:[],cpu_percent:null,memory_percent:null,disk_percent:null,wal_pending:0}:path==='/capture-config'?{interfaces:[],status:'not_applied'}:path==='/platform/health'?{services:{},runtime:{errors:[],heap_bytes:'0',goroutines:1}}:{items:[],next_cursor:'',available:true}));window.history.replaceState({},'','/login')})

 describe('显示和安全回跳',()=>{
 it('整数字符串、不同数量级和缺测采用有界格式且排序保留精度',()=>{
  for(const value of [null,undefined,'',-1,-1n,NaN,Infinity,'invalid'])expect(formatBytes(value)).toBe('未获取')
  expect(formatBytes('18446744073709551615')).toBe('18.45 EB');expect(formatBytes(1024,true)).toBe('1 KiB');expect(formatBytes('999999')).toBe('1 MB');expect(formatBytes(999999)).toBe('1 MB');expect(formatBytes(0n)).toBe('0 B');expect(formatBytes(10n**40n)).toContain('>1000000');expect(formatBitRate(10**35)).toContain('>1000000');expect(formatBitRate(1000000)).toBe('1 Mbit/s')
  expect(formatQuantity(null)).toBe('未提供');expect(formatQuantity(1000)).toBe('1 KB');expect(formatQuantity(1024n)).toBe('1.02 KB');expect(formatQuantity(' 1200000 ')).toBe('1.2 MB');expect(formatQuantity('unknown')).toBe('unknown');expect(formatQuantity('1.5 KiB')).toBe('1.5 KiB');expect(formatQuantity('2 Mbit/s')).toBe('2 Mbit/s');expect(formatQuantity('9 B')).toBe('9 B')
  expect(compareQuantity('18446744073709551615','18446744073709551614')).toBe(1);expect(compareQuantity('1 KiB','1.024 KB')).toBe(0);expect(compareQuantity('1 Mbit/s','2 Mbit/s')).toBe(-1);expect(compareQuantity(null,undefined)).toBe(0);expect(compareQuantity('a2','a10')).toBeLessThan(0);expect(compareQuantity('1 B','1 bit/s')).not.toBeNaN()
  expect(formatTime(null)).toBe('未获取');expect(formatPercent(null)).toBe('未获取');expect(formatPercent(10)).toBe('10.0%');expect(formatHealthErrors([])).toBe('无已报告异常');expect(formatHealthErrors(['cpu_unavailable','future'])).toContain('未识别的观测异常')
  expect(formatHealthErrors(['task_history_cleanup_unavailable'])).toBe('任务历史清理未完成，请核对本地存储；原记录继续保留')
 })
 it('回跳拒绝外部、控制字符、编码绕过和登录循环，兼容旧地址',()=>{
  for(const value of [null,[],42,'https://example.test','//evil.test','/\\evil','/%5cevil','/%00bad','/%2f%2fevil','/%GG','/login','/login/other'])expect(safeReturnPath(value,'/sensors')).toBe('/sensors')
  expect(safeReturnPath('/alerts?view=data#detail','/sensors')).toBe('/alerts?view=data#detail');expect(safeReturnPath('/login','/',true)).toBe('/login')
  window.history.replaceState({},'','/old#/alerts?severity=high');migrateLegacyHash('/console/');expect(window.location.pathname).toBe('/console/alerts');expect(window.location.search).toBe('?severity=high');window.history.replaceState({},'','/login#section');migrateLegacyHash();expect(window.location.hash).toBe('#section')
 })
 it('浅色配色覆盖根节点与弹窗，背景与边界保持正式主题值',()=>{
  applyPalette();expect(document.documentElement.style.getPropertyValue('--workspace')).toBe('#f7f7f7');expect(document.documentElement.style.getPropertyValue('--syntax-variable')).toBe(palette.syntaxVariable);expect(appTheme.token.colorBgContainer).toBe('#ffffff');expect(appTheme.components.Table.colorFillAlter).toBe('#fafafa')
 })
 })

 describe('导航壳层',()=>{
 it('桌面折叠、移动抽屉、导航和退出均可操作',async()=>{
  const match=vi.mocked(window.matchMedia);match.mockReturnValue({matches:false,media:'',onchange:null,addListener:vi.fn(),removeListener:vi.fn(),addEventListener:vi.fn(),removeEventListener:vi.fn(),dispatchEvent:vi.fn()});const wrapper=mount(AppShell,{props:{title:'采集器管理',username:'admin',current:'/network',items:[{key:'/network',label:'网络与采集',icon:()=>h('span','N')}]},slots:{default:'工作区内容'},global:{plugins:[registerAnt]},attachTo:document.body});expect(wrapper.text()).toContain('工作区内容');await wrapper.get('[aria-label=收起导航]').trigger('click');expect(wrapper.find('[aria-label=展开导航]').exists()).toBe(true);await wrapper.get('[aria-label=展开导航]').trigger('click');await click('退出');expect(wrapper.emitted('logout')).toHaveLength(1)
  wrapper.getComponent(Menu).vm.$emit('click',{key:'/network'});await flushPromises();expect(wrapper.emitted('navigate')).toEqual([['/network']]);match.mockReturnValue({matches:true,media:'',onchange:null,addListener:vi.fn(),removeListener:vi.fn(),addEventListener:vi.fn(),removeEventListener:vi.fn(),dispatchEvent:vi.fn()});await wrapper.get('[aria-label=收起导航]').trigger('click');await flushPromises();expect(document.body.querySelector('.ant-drawer-open')).not.toBeNull();(document.body.querySelector('.ant-drawer-close') as HTMLButtonElement).click();await flushPromises()
 })
 })

 describe('应用入口、路由和登录',()=>{
 it('平台实际路由拒绝未登录和越权访问，并保留站内回跳地址',async()=>{
  const{session}=await import('../platform/src/session'),user=session.current as ShallowRef<Principal|null>,{router}=await import('../platform/src/router')
  user.value=null;await router.push('/sensors?view=tasks');expect(router.currentRoute.value.path).toBe('/login');expect(router.currentRoute.value.query.redirect).toBe('/sensors?view=tasks')
  restore.mockRejectedValueOnce(new Error('session unavailable'));await router.push('/alerts');expect(router.currentRoute.value.path).toBe('/login')
  user.value={...principal,role:'viewer'};await router.push('/operations');expect(router.currentRoute.value.path).toBe('/sensors')
 })
 it.each([
  ['/alerts','告警管理'],['/traffic','流量检索'],['/rules','规则管理'],['/assets','资产管理'],['/operations','运行与审计'],['/overview','态势总览'],['/screen','态势大屏'],['/notifications','通知中心'],['/models','模型配置'],['/assistant','智能助手'],['/reports','报告中心'],['/retention','数据留存'],['/incidents','事件调查'],['/users','用户管理'],['/unknown','页面不存在'],
 ])('平台地址 %s 可直接打开并展示 %s',async(path,title)=>{
  const{session}=await import('../platform/src/session'),{router}=await import('../platform/src/router'),{default:App}=await import('../platform/src/App.vue')
  const user=session.current as ShallowRef<Principal|null>;user.value=principal;await router.push(path)
  const wrapper=mount(App,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises()
  expect(wrapper.text()).toContain(title);wrapper.unmount()
 })
 it('平台登录拒绝外部回跳，失效会话和退出结果驱动导航',async()=>{
  const{session}=await import('../platform/src/session'),user=session.current as ShallowRef<Principal|null>,{router}=await import('../platform/src/router'),{default:App}=await import('../platform/src/App.vue')
  user.value=null;await router.push('/login?redirect=https://evil.test')
  const wrapper=mount(App,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises()
  const form=wrapper.findComponent({name:'LoginForm'});form.vm.$emit('submit','admin','password');await flushPromises();expect(router.currentRoute.value.path).toBe('/login')
  login.mockImplementationOnce(async()=>{user.value=principal;return true});form.vm.$emit('submit','admin','password');await flushPromises();expect(router.currentRoute.value.path).toBe('/sensors')
  user.value=null;await flushPromises();expect(router.currentRoute.value.path).toBe('/login')
  user.value=principal;await router.push('/sensors');await flushPromises();logout.mockRejectedValueOnce(new Error('退出受阻'));await click('退出');expect(router.currentRoute.value.path).toBe('/sensors')
  await click('退出');expect(router.currentRoute.value.path).toBe('/login');wrapper.unmount()
 })
 it('平台浏览器入口挂载登录页并可卸载应用',async()=>{
  const{session}=await import('../platform/src/session'),{router}=await import('../platform/src/router')
  const user=session.current as ShallowRef<Principal|null>;user.value=null;await router.push('/login');document.body.innerHTML='<div id="app"></div>'
  await import('../platform/src/main');await flushPromises();expect(document.body.textContent).toContain('登录星烽')
  const app=(document.getElementById('app') as HTMLElement&{__vue_app__:{unmount:()=>void}}).__vue_app__;app.unmount()
 })
 it('采集器实际路由保护本地管理，入口与默认网络视图一致',async()=>{
  const{session}=await import('../collector/src/session'),user=session.current as ShallowRef<Principal|null>,{router}=await import('../collector/src/router');user.value=null;await router.push('/network?view=capture');expect(router.currentRoute.value.path).toBe('/login');restore.mockRejectedValueOnce(new Error('session unavailable'));await router.push('/network?view=tasks');expect(router.currentRoute.value.path).toBe('/login');user.value=principal;await router.push('/');expect(router.currentRoute.value.path).toBe('/network')
  const{default:App}=await import('../collector/src/App.vue');const wrapper=mount(App,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('网络与采集');await router.push('/unknown');await flushPromises();expect(wrapper.text()).toContain('页面不存在');await router.push('/login?redirect=%2Fnetwork%3Fview%3Dcapture');await flushPromises();const form=wrapper.findComponent({name:'LoginForm'});form.vm.$emit('submit','admin','password');await flushPromises();expect(router.currentRoute.value.path).toBe('/login');login.mockResolvedValueOnce(true);form.vm.$emit('submit','admin','password');await flushPromises();expect(router.currentRoute.value.query.view).toBe('capture');user.value=null;await flushPromises();expect(router.currentRoute.value.path).toBe('/login');user.value=principal;await router.push('/network');await flushPromises();logout.mockRejectedValueOnce('offline');await click('退出');expect(router.currentRoute.value.path).toBe('/network');await click('退出');expect(router.currentRoute.value.path).toBe('/login');wrapper.unmount()
  document.body.innerHTML='<div id="app"></div>';await import('../collector/src/main');await flushPromises();expect(document.body.textContent).toContain('登录采集器');const app=(document.getElementById('app') as HTMLElement&{__vue_app__:{unmount:()=>void}}).__vue_app__;app.unmount()
 })
 })
