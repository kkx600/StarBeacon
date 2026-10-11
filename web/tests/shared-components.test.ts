import {closedMessage} from './fixtures'
import {describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {message} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import StatePanel from '../packages/shared/src/components/StatePanel.vue'
import WorkspaceTabs from '../packages/shared/src/components/WorkspaceTabs.vue'
import LoginForm from '../packages/shared/src/components/LoginForm.vue'
import ByteViewer from '../packages/shared/src/components/ByteViewer.vue'
import NotFound from '../packages/shared/src/components/NotFound.vue'
import {createMemoryHistory,createRouter} from 'vue-router'

const global={plugins:[registerAnt]}
const button=(wrapper:ReturnType<typeof mount>,label:string)=>{const match=wrapper.findAll('button').find(button=>button.text().replace(/\s/g,'')===label);expect(match,`按钮 ${label} 应可操作`).toBeDefined();return match!}

describe('通用工作区状态',()=>{
  it('加载、错误、无数据和内容互斥，失败提供重试',async()=>{
    const wrapper=mount(StatePanel,{props:{loading:true,error:'连接失败',empty:true},slots:{default:'业务内容'},global})
    expect(wrapper.get('[role=status]').text()).toContain('正在读取数据');expect(wrapper.text()).not.toContain('业务内容')
    await wrapper.setProps({loading:false});expect(wrapper.get('[role=alert]').text()).toContain('连接失败');await button(wrapper,'重试').trigger('click');expect(wrapper.emitted('retry')).toHaveLength(1)
    await wrapper.setProps({error:''});expect(wrapper.text()).toContain('暂无记录');await wrapper.setProps({description:'当前范围没有告警'});expect(wrapper.text()).toContain('当前范围没有告警')
    await wrapper.setProps({empty:false});expect(wrapper.text()).toBe('业务内容')
  })
  it('页签按当前值展示且提供可访问的导航标记',async()=>{
    const wrapper=mount(WorkspaceTabs,{props:{active:'devices',items:[{key:'devices',label:'探针列表'},{key:'tasks',label:'任务记录'}],label:'探针管理功能'},global})
    expect(wrapper.get('nav').attributes('aria-label')).toBe('探针管理功能');expect(wrapper.get('[aria-selected=true]').text()).toBe('探针列表')
    await wrapper.findAll('[role=tab]')[1]!.trigger('click');expect(wrapper.emitted('change')).toEqual([['tasks']])
  })
  it('未知地址提供可用的返回入口',async()=>{
    const router=createRouter({history:createMemoryHistory(),routes:[{path:'/sensors',component:StatePanel}]});await router.push('/sensors');await router.isReady()
    const wrapper=mount(NotFound,{props:{home:'/sensors'},global:{plugins:[registerAnt,router]}})
    expect(wrapper.text()).toContain('页面');expect(wrapper.get('a').attributes('href')).toBe('/sensors')
  })
})

describe('登录交互',()=>{
  it('校验必填内容后提交，清除密码且展示服务错误',async()=>{
    const wrapper=mount(LoginForm,{props:{title:'采集器管理',pending:false,error:''},global})
    await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.emitted('submit')).toBeUndefined();await vi.waitFor(()=>expect(wrapper.text()).toContain('请输入账号'))
    const fields=wrapper.findAll('input');await fields[0]!.setValue('admin');await fields[1]!.setValue('example-password');await wrapper.get('form').trigger('submit');await flushPromises()
    expect(wrapper.emitted('submit')).toEqual([['admin','example-password']]);expect((fields[1]!.element as HTMLInputElement).value).toBe('')
    await wrapper.setProps({pending:true,error:'账号或密码错误'});expect(fields[0]!.attributes('disabled')).toBeDefined();expect(wrapper.text()).toContain('账号或密码错误')
  })
})

describe('字节证据交互',()=>{
  it('展示有来源的 HEX，切换 UTF-8 并复制当前内容',async()=>{
    const success=vi.spyOn(message,'success').mockImplementation(closedMessage),writeText=vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator,'clipboard',{value:{writeText},configurable:true})
    const wrapper=mount(ByteViewer,{props:{original:JSON.stringify({payload:btoa('GET /api HTTP/1.1')})},global})
    expect(wrapper.get('pre').text()).toContain('00000000');expect(wrapper.text()).toContain('应用载荷字节');await wrapper.findAll('input[type=radio]')[1]!.setValue();expect(wrapper.get('pre').text()).toBe('GET /api HTTP/1.1')
    await button(wrapper,'复制当前内容').trigger('click');await flushPromises();expect(writeText).toHaveBeenCalledWith('GET /api HTTP/1.1');expect(success).toHaveBeenCalled()
  })
  it('分页只渲染局部字节，更换记录重置分页和显示方式',async()=>{
    const wrapper=mount(ByteViewer,{props:{original:JSON.stringify({packet:btoa('a'.repeat(700))})},global})
    expect(wrapper.get('pre').text().split('\n')).toHaveLength(16);await wrapper.get('.ant-pagination-next').trigger('click');expect(wrapper.get('pre').text()).toContain('00000100')
    await wrapper.setProps({original:JSON.stringify({payload:btoa('new')})});expect(wrapper.get('pre').text()).toContain('00000000');expect(wrapper.find('.ant-pagination').exists()).toBe(false)
  })
  it('缺失、坏编码和无效 UTF-8 均不会伪装成完整数据包',async()=>{
    const wrapper=mount(ByteViewer,{props:{original:'{}'},global});expect(wrapper.find('pre').exists()).toBe(false);expect(wrapper.text()).toContain('字节')
    await wrapper.setProps({original:'{"packet":"bad@"}'});expect(wrapper.find('pre').exists()).toBe(false)
    await wrapper.setProps({original:JSON.stringify({packet:btoa('\xff\x00')})});await wrapper.findAll('input[type=radio]')[1]!.setValue();expect(wrapper.text()).toContain('无效 UTF-8');expect(wrapper.find('pre').exists()).toBe(false);expect(wrapper.findAll('button').some(button=>button.text()==='复制当前内容')).toBe(false)
  })
  it('复制权限失败时提供可读提示',async()=>{
    const error=vi.spyOn(message,'error').mockImplementation(closedMessage)
    Object.defineProperty(navigator,'clipboard',{value:{writeText:vi.fn().mockRejectedValue(new Error('denied'))},configurable:true})
    const wrapper=mount(ByteViewer,{props:{original:JSON.stringify({packet:btoa('ok')})},global});await button(wrapper,'复制当前内容').trigger('click');await flushPromises();expect(error).toHaveBeenCalledWith('复制失败，请选择内容后手动复制')
  })
  it('搜索跨页 UTF-8 文本后定位 HEX，切换匹配并重置过期结果',async()=>{
    const wrapper=mount(ByteViewer,{props:{original:JSON.stringify({payload:btoa('x'.repeat(255)+'GET'+'x'.repeat(250)+'GET')})},global})
    const input=wrapper.get('.byte-search input:not([type=radio])');expect(wrapper.get('.byte-search label[for]').attributes('for')).toBe(input.attributes('id'))
    await input.setValue('GET');await wrapper.get('form').trigger('submit')
    expect(wrapper.get('[role=status]').text()).toContain('2 处匹配');expect(wrapper.text()).toContain('0x000000ff（255 B）');expect(wrapper.get('mark').text()).toBe('47')
    await button(wrapper,'下一处').trigger('click');expect(wrapper.text()).toContain('0x000001fc（508 B）');expect(wrapper.get('pre').text()).toContain('00000100');expect(wrapper.get('mark').text()).toBe('47 45 54')
    expect(button(wrapper,'下一处').attributes('disabled')).toBeDefined();await button(wrapper,'上一处').trigger('click');expect(button(wrapper,'上一处').attributes('disabled')).toBeDefined()
    await wrapper.get('.ant-pagination-next').trigger('click');expect(wrapper.get('pre').text()).toContain('00000100');await button(wrapper,'定位当前').trigger('click');expect(wrapper.get('pre').text()).toContain('00000000')
    await input.setValue('missing');expect(wrapper.find('[role=status]').exists()).toBe(false);expect(wrapper.find('mark').exists()).toBe(false)
    await wrapper.get('form').trigger('submit');expect(wrapper.get('[role=status]').text()).toBe('未找到匹配内容')
    await wrapper.setProps({original:JSON.stringify({payload:btoa('new')})});expect(wrapper.find('[role=status]').exists()).toBe(false);expect((wrapper.get('.byte-search input:not([type=radio])').element as HTMLInputElement).value).toBe('')
  })
  it('错误 HEX 输入关联错误提示，查找结果上限明确可见',async()=>{
    const wrapper=mount(ByteViewer,{props:{original:JSON.stringify({packet:btoa('\xff'.repeat(1200))})},global})
    await wrapper.get('.byte-search input:not([type=radio])').setValue('ff');await wrapper.findAll('.byte-search input[type=radio]')[1]!.setValue();await wrapper.get('form').trigger('submit')
    expect(wrapper.get('[role=status]').text()).toContain('前 1,000 处匹配');expect(wrapper.text()).toContain('仅保留前 1,000 处')
    await wrapper.get('.byte-search input:not([type=radio])').setValue('f');await wrapper.get('form').trigger('submit')
    const input=wrapper.get('.byte-search input:not([type=radio])');expect(input.attributes('aria-invalid')).toBe('true');expect(wrapper.get('[role=alert]').attributes('id')).toBe(input.attributes('aria-describedby'))
    expect(wrapper.find('mark').exists()).toBe(false);expect(wrapper.find('[role=status]').exists()).toBe(false)
    await input.setValue('ff');await wrapper.get('form').trigger('submit');expect(input.attributes('aria-invalid')).toBe('false');expect(wrapper.get('mark').text()).toBe('ff')
  })
})
