import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import MCPWorkspace from '../platform/src/features/mcp/MCPWorkspace.vue'
import MCPResourceGuide from '../platform/src/features/mcp/MCPResourceGuide.vue'
import type {MCPInfo} from '../platform/src/features/mcp/mcp'
import {click,deferred} from './fixtures'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',()=>({session:{api:{request}}}))
const info:MCPInfo={enabled:true,resource:'https://soc.example/mcp',issuer:'https://issuer.example',metadata_url:'https://soc.example/.well-known/oauth-protected-resource/mcp',protocol_versions:['2026-07-28'],tools:[{name:'alerts.search',title:'告警检索',scope:'alerts:read',description:'受限告警元数据检索'}]}
const clipboardDescriptor=Object.getOwnPropertyDescriptor(navigator,'clipboard')
const writeText=vi.fn<(_value:string)=>Promise<void>>()
beforeEach(()=>{
  request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path==='/mcp'?info:{items:[]}))
  writeText.mockReset();writeText.mockResolvedValue(undefined)
  Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText}})
})
afterEach(()=>{if(clipboardDescriptor)Object.defineProperty(navigator,'clipboard',clipboardDescriptor);else Reflect.deleteProperty(navigator,'clipboard')})

async function copyButton(label:string){const button=document.querySelector<HTMLButtonElement>('button[aria-label="'+label+'"]');expect(button).not.toBeNull();button!.click();await flushPromises();return button!}

describe('MCP 元数据资源接入',()=>{
  it('从独立页签了解资源并复制准确 URI，不使用管理会话伪造 Agent 发现',async()=>{
    const wrapper=mount(MCPWorkspace,{global:{plugins:[registerAnt]},attachTo:document.body});await flushPromises()
    await click('工具与资源');expect(document.querySelector('[role=dialog]')?.textContent).toContain('受限告警元数据检索')
    await click('元数据资源');const dialog=document.querySelector('[role=dialog]')!
    expect(dialog.textContent).not.toContain('受限告警元数据检索')
    expect(dialog.textContent).toContain('不是当前身份的发现结果')
    expect(dialog.textContent).toContain('resources/list');expect(dialog.textContent).toContain('resources/templates/list');expect(dialog.textContent).toContain('resources/read')
    expect(dialog.textContent).toContain('alerts:read');expect(dialog.textContent).toContain('traffic:read');expect(dialog.textContent).toContain('任一已授权只读权限')
    expect(dialog.querySelectorAll('table')).toHaveLength(0);expect(wrapper.findAll('.ant-table')).toHaveLength(0)
    await copyButton('复制协议检索字段地址');expect(writeText).toHaveBeenLastCalledWith('starbeacon://catalog/context/fields')
    expect(document.querySelector('[aria-label="复制协议检索字段地址"]')?.textContent).toContain('已复制')
    await copyButton('复制字段资源模板');expect(writeText).toHaveBeenLastCalledWith('starbeacon://catalog/{dataset}/fields')
    expect(request.mock.calls.map(call=>call[0])).toEqual(['/mcp','/mcp/bindings'])
    expect(info).not.toHaveProperty('resources')
  })

  it('关闭目录后恢复默认工具页签，资源说明与复制状态不滞留',async()=>{
    mount(MCPWorkspace,{global:{plugins:[registerAnt]},attachTo:document.body});await flushPromises()
    await click('工具与资源');await click('元数据资源');await copyButton('复制分析能力说明地址')
    ;(document.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises()
    expect(document.body.textContent).not.toContain('不是当前身份的发现结果')
    await click('工具与资源');expect(document.querySelector('[role=tab][aria-selected=true]')?.textContent).toBe('工具目录')
    expect(document.querySelector('[role=dialog]')?.textContent).toContain('受限告警元数据检索')
    await click('元数据资源');expect(document.querySelector('[aria-label="复制分析能力说明地址"]')?.textContent).toContain('复制地址')
  })

  it('未启用服务仍可阅读接入说明，不把文档显示视为接入成功',async()=>{
    request.mockImplementation((path:string)=>Promise.resolve(path==='/mcp'?{...info,enabled:false,tools:[]}:{items:[]}))
    mount(MCPWorkspace,{global:{plugins:[registerAnt]},attachTo:document.body});await flushPromises()
    expect(document.body.textContent).toContain('MCP 服务尚未启用')
    await click('工具与资源');expect(document.body.textContent).toContain('尚未取得工具目录')
    await click('元数据资源');expect(document.body.textContent).toContain('不是当前身份的发现结果')
    expect(document.body.textContent).toContain('不提供原始载荷、PCAP、任意文件下载或设备执行权限')
    expect([...document.querySelectorAll('button')].find(button=>button.textContent?.replaceAll(' ','')==='登记服务身份')?.disabled).toBe(true)
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('目录读取失败保留真实错误和重试，静态资源说明不遮盖服务状态',async()=>{
    request.mockRejectedValue(new Error('授权配置读取失败'))
    mount(MCPWorkspace,{global:{plugins:[registerAnt]},attachTo:document.body});await flushPromises()
    await click('工具与资源');expect(document.querySelector('[role=dialog]')?.textContent).toContain('授权配置读取失败')
    expect(document.querySelector('[role=dialog]')?.querySelector('button')?.textContent).toBeDefined()
    await click('元数据资源');expect(document.body.textContent).toContain('授权配置读取失败');expect(document.body.textContent).toContain('不是当前身份的发现结果')
    request.mockImplementation((path:string)=>Promise.resolve(path==='/mcp'?info:{items:[]}))
    await click('工具目录');await click('重试',document.querySelector('[role=dialog]')!)
    expect(document.querySelector('[role=dialog]')?.textContent).toContain('受限告警元数据检索');expect(document.body.textContent).not.toContain('授权配置读取失败')
  })

  it('剪贴板拒绝时提供手动复制出口，再次成功后清理错误',async()=>{
    mount(MCPResourceGuide,{attachTo:document.body});writeText.mockRejectedValueOnce(new Error('permission denied'))
    await copyButton('复制告警检索字段地址')
    expect(document.body.textContent).toContain('无法访问剪贴板，请选择资源地址后手动复制')
    expect(document.querySelector('[aria-label="复制告警检索字段地址"]')?.textContent).not.toContain('已复制')
    expect([...document.querySelectorAll('code')].some(code=>code.textContent==='starbeacon://catalog/alerts/fields')).toBe(true)
    await copyButton('复制告警检索字段地址');expect(document.body.textContent).not.toContain('无法访问剪贴板')
    expect(document.querySelector('[aria-label="复制告警检索字段地址"]')?.textContent).toContain('已复制')
  })

  it('剪贴板不可用时不显示复制成功，离开页面后的迟到结果不恢复界面',async()=>{
    Object.defineProperty(navigator,'clipboard',{configurable:true,value:undefined})
    const wrapper=mount(MCPResourceGuide,{attachTo:document.body})
    await copyButton('复制分析能力说明地址');expect(document.body.textContent).toContain('无法访问剪贴板');expect(writeText).not.toHaveBeenCalled()
    const pending=deferred<void>();writeText.mockReturnValueOnce(pending.promise);Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText}})
    await copyButton('复制分析能力说明地址');expect(document.querySelector('[aria-label="复制告警检索字段地址"]')?.getAttribute('disabled')).not.toBeNull()
    wrapper.unmount();pending.resolve();await flushPromises();expect(document.body.textContent).not.toContain('已复制')
  })
})
