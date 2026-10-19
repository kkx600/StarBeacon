import {beforeEach,describe,it,expect,vi} from 'vitest'
import {mount,flushPromises} from '@vue/test-utils'
import {defineComponent,h} from 'vue'
import {createRouter,createMemoryHistory,RouterView} from 'vue-router'
import {Menu,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import NavigationMenu from '../packages/shared/src/components/NavigationMenu.vue'
import WorkspaceTabs from '../packages/shared/src/components/WorkspaceTabs.vue'
import SettingsWorkspace from '../platform/src/features/settings/SettingsWorkspace.vue'
import UnavailableView from '../platform/src/views/UnavailableView.vue'
import {navigationGroups,navigationWorkspaces,platformScreens,workspacePath} from '../packages/shared/src/navigation'
import {legacyDestination,navigationForRole,platformRoutes} from '../platform/src/navigation'
import {useWorkspaceView} from '../packages/shared/src/utils/useWorkspaceView'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>{
 const {shallowRef}=await import('vue')
 return {session:{api:{request},current:shallowRef({id:'admin_example',tenant_id:'tenant_example',role:'admin',csrf_token:'csrf_example'})}}
})
beforeEach(()=>request.mockReset().mockResolvedValue({items:[],next_cursor:'',available:false,execution_available:false,model_execution_available:false,enabled:false,tools:[]}))
const global={plugins:[registerAnt]}
async function routerFor(path:string){const router=createRouter({history:createMemoryHistory(),routes:platformRoutes()});await router.push(path);await router.isReady();return router}

describe('业务导航与路由契约',()=>{
 it.each(['/inventory/list','/inventory/groups','/inventory/networks','/inventory/discovery','/ai/assistant','/response/policies','/response/evaluations','/ai/mcp','/reports/plans'])('实际路由 %s 的页面标题与导航名称一致',async path=>{
  const router=await routerFor(path),screen=platformScreens.find(item=>item.path===path)!
  const wrapper=mount(RouterView,{global:{plugins:[registerAnt,router]}})
  try{await flushPromises();expect(wrapper.get('h1').text()).toBe(screen.title)}finally{wrapper.unmount()}
 })
 it('十二个业务分组与四十三个原型工作区都有稳定入口，深层页面确实由父子路由匹配',async()=>{
  expect(navigationGroups).toHaveLength(12);expect(navigationWorkspaces).toHaveLength(43)
  const router=await routerFor('/system/accounts/users')
  expect(router.currentRoute.value.matched.map(record=>record.path)).toEqual(['/system','/system/accounts','/system/accounts/users'])
  expect(router.currentRoute.value.meta).toMatchObject({navGroup:'system',navWorkspace:'users',admin:true})
  for(const screen of platformScreens){const target=router.resolve(screen.path);expect(target.matched.at(-1)?.components?.default).toBeTruthy();expect(target.meta.title).toBe(screen.title);expect(target.meta.workspaceView).toBe(screen.view)}
  for(const workspace of navigationWorkspaces)expect(router.resolve(workspacePath(workspace)).matched.length).toBeGreaterThan(0)
  for(const path of ['/system','/system/accounts','/detection','/detection/rules']){await router.push(path);expect(router.currentRoute.value.matched.at(-1)?.components?.default).toBeTruthy()}
 })
 it.each([
  ['/sensors','/sensors/list'],['/models','/ai/models'],['/rules','/detection/rules/packages'],['/operations','/system/operations/health'],
  ['/sensors?view=quality','/traffic/capture/quality'],['/models?view=policies','/response/policies'],['/models?view=mcp','/ai/mcp'],
  ['/rules?view=sync&mode=rollouts','/detection/rules/rollouts'],['/rules?view=sync','/detection/rules/sync'],
  ['/models?view=invalid','/ai/models'],['/unknown','/sensors/list'],
 ])('旧链接 %s 进入相同业务，并保留检索窗口及定位标记',async(input,expected)=>{
  const url=new URL('https://example.test'+input);const query=Object.fromEntries(url.searchParams)
  const result=legacyDestination({path:url.pathname,query:{...query,start:'2026-10-19T00:00:00Z',end:'2026-10-20T00:00:00Z'},hash:'#evidence'})
  expect(result).toEqual({path:expected,query:{start:'2026-10-19T00:00:00Z',end:'2026-10-20T00:00:00Z'},hash:'#evidence'})
 })
 it('只读角色不显示管理员及未提供的工作区，管理员可定位全部设计目录',()=>{
  const viewer=navigationForRole(false),admin=navigationForRole(true)
  expect(admin.flatMap(group=>group.children)).toHaveLength(43)
  expect(viewer.flatMap(group=>group.children).some(item=>['users','models','mcp','decision-policies','tenants'].includes(item.key))).toBe(false)
  expect(viewer.flatMap(group=>group.children).every(item=>item.available)).toBe(true)
  expect(admin.find(group=>group.key==='system')?.children.map(item=>item.label)).toContain('平台运维')
 })
 it('页签沿规范路径切换、移除旧路由选择参数，保留业务条件并支持返回',async()=>{
  const router=await routerFor('/system/audit/operations?start=2026-10-19&view=legacy&mode=legacy#detail')
  const Probe=defineComponent({setup(){const {view,change}=useWorkspaceView(['health','operations','logins']);return {view,change}},template:'<button @click="change(\'logins\')">{{view}}</button>'})
  const wrapper=mount(Probe,{global:{plugins:[router]}})
  expect(wrapper.text()).toBe('operations');await wrapper.get('button').trigger('click');await flushPromises();expect(router.currentRoute.value.fullPath).toBe('/system/audit/logins?start=2026-10-19#detail')
  router.back();await vi.waitFor(()=>expect(router.currentRoute.value.path).toBe('/system/audit/operations'));wrapper.unmount()
 })
 it('模型页不再混入决策与 MCP，原生发布模式页签保持可操作',async()=>{
  const router=await routerFor('/ai/models');const wrapper=mount(WorkspaceTabs,{props:{active:'providers',label:'功能',items:[{key:'providers',label:'模型提供方'},{key:'policies',label:'决策策略'},{key:'mcp',label:'MCP 服务'}]},global:{plugins:[registerAnt,router]}})
  expect(wrapper.find('nav').exists()).toBe(false);await router.push('/detection/rules/sync');await wrapper.setProps({active:'plans',items:[{key:'plans',label:'单探针计划'},{key:'rollouts',label:'分批发布'}]});expect(wrapper.text()).toContain('分批发布');wrapper.unmount()
 })
 it('展开祖先分组、切换与折叠不会丢失当前选中工作区',async()=>{
  const items=[{key:'group:system',label:'系统管理',children:[{key:'workspace:users',label:'账号与权限'}]},{key:'other',label:'其他',icon:()=>h('span')}]
  const wrapper=mount(NavigationMenu,{props:{items,current:'workspace:users'},global})
  expect(wrapper.getComponent(Menu).props('openKeys')).toEqual(['group:system'])
  await wrapper.setProps({collapsed:true});expect(wrapper.getComponent(Menu).props('openKeys')).toEqual([])
  await wrapper.setProps({collapsed:false});expect(wrapper.getComponent(Menu).props('selectedKeys')).toEqual(['workspace:users'])
  wrapper.getComponent(Menu).vm.$emit('click',{key:'workspace:users'});expect(wrapper.emitted('navigate')).toEqual([['workspace:users']])
  await wrapper.setProps({current:'missing'});expect(wrapper.getComponent(Menu).props('openKeys')).toEqual([]);wrapper.unmount()
 })
 it('系统设置只链接可用功能，查询与空结果不会生成虚假配置操作',async()=>{
  const router=await routerFor('/system/settings');const wrapper=mount(SettingsWorkspace,{global:{plugins:[registerAnt,router]}})
  expect(wrapper.findAll('.ant-table-wrapper')).toHaveLength(1);expect(wrapper.text()).toContain('当前版本未提供')
  const disabled=wrapper.findAll('button').filter(button=>button.attributes('disabled')!==undefined);expect(disabled.length).toBeGreaterThan(0)
  await wrapper.get('input').setValue('不存在的设置');expect(wrapper.text()).toContain('没有匹配的设置项')
  await wrapper.get('input').setValue('');wrapper.getComponent(Select).vm.$emit('update:value','all');await flushPromises();expect(wrapper.text()).toContain('检测规则')
  const users=wrapper.findAll('tr').find(row=>row.text().includes('账号与权限'))!;await users.get('button').trigger('click');await vi.waitFor(()=>expect(router.currentRoute.value.path).toBe('/system/accounts/users'));wrapper.unmount()
 })
 it('尚未提供的目录清楚说明范围，系统设置与总览返回目标有效',async()=>{
  const router=await routerFor('/system/tenants');const wrapper=mount(UnavailableView,{global:{plugins:[registerAnt,router]}})
  expect(wrapper.get('h1').text()).toBe('租户管理');expect(wrapper.text()).toContain('当前版本未提供此功能')
  await wrapper.findAll('button')[0]!.trigger('click');await vi.waitFor(()=>expect(router.currentRoute.value.path).toBe('/system/settings'))
  await wrapper.findAll('button')[1]!.trigger('click');await vi.waitFor(()=>expect(router.currentRoute.value.path).toBe('/overview/dashboard'));wrapper.unmount()
 })
})
