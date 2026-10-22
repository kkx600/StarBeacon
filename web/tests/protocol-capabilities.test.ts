import { describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { registerAnt } from '../packages/shared/src/ant'
import ProtocolCapabilities from '../packages/shared/src/components/ProtocolCapabilities.vue'
import ProtocolCapabilitiesDialog from '../packages/shared/src/components/ProtocolCapabilitiesDialog.vue'
import { isProtocolReport, protocolLimitNames } from '../packages/shared/src/protocols'
import type { ProtocolEntry, ProtocolReport } from '../packages/shared/src/protocols'

function sample(): ProtocolReport {
  const row: ProtocolEntry = {protocol:'http',name:'HTTP/1',bindings:[{transport:'tcp',mode:'yes'}],native_listed:true,recognition:'configured',transactions:'configured',online_rules:'requires_validation',file_extraction:'not_implemented',packet_forensics:'not_implemented',external_logs:'not_implemented',qualification:'not_qualified'}
  return {schema_version:1,state:'observed',observed_at:'2026-10-14T00:00:00Z',source:'managed_configuration',capture_active:true,engine_version:'8.0.7',engine_sha256:'a'.repeat(64),config_sha256:'b'.repeat(64),protocols:[row,{...row,protocol:'tls',name:'TLS',transactions:'unknown'},{...row,protocol:'imap',name:'IMAP',bindings:[{transport:'tcp',mode:'detection-only'}],recognition:'detection_only',transactions:'disabled',online_rules:'disabled'},{...row,protocol:'tcp',name:'TCP',bindings:[],native_listed:false,recognition:'unknown',transactions:'unknown',packet_forensics:'packet_headers_only'}],limits:Object.keys(protocolLimitNames).map((key,i)=>({key,value:i===3?'0':i===6?'':'32mb'}))}
}
const mountReport = (report:unknown=sample()) => mount(ProtocolCapabilities,{props:{report},attachTo:document.body,global:{plugins:[registerAnt]}})

describe('协议能力的来源、边界和交互',()=>{
  it('分别呈现六层状态和实际摘要，不把 TLS 或规则目录视为效果资格',async()=>{
    const wrapper=mountReport()
    expect(wrapper.text()).toContain('可见握手不代表解密')
    expect(wrapper.text()).toContain('需规则样本验证')
    expect(wrapper.text()).toContain('仅识别')
    expect(wrapper.text()).toContain('有界包头解析')
    expect(wrapper.text()).not.toContain('a'.repeat(64))
    await wrapper.findAll('button').find(button=>button.text()==='查看来源')!.trigger('click');await flushPromises()
    expect(document.body.textContent).toContain('a'.repeat(64))
    document.querySelector<HTMLButtonElement>('.ant-modal-close')!.click();await flushPromises()
    expect(wrapper.findAll('.ant-table-wrapper')).toHaveLength(1)
    await wrapper.get('input[aria-label="筛选协议"]').setValue('IMAP')
    expect(wrapper.text()).toContain('1 / 4 项')
    expect(wrapper.findAll('tbody tr[data-row-key]')).toHaveLength(1)
    await wrapper.get('button[aria-label="查看 IMAP 协议能力"]').trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('未完成独立正反例及非标准端口验收')
    expect(document.body.textContent).toContain('TCP · 仅识别')
    const close=document.querySelector<HTMLButtonElement>('.ant-modal-close')!
    close.click();await flushPromises()
    expect(document.body.textContent).not.toContain('TCP · 仅识别')
  })
  it('无观测、未知 schema、取消与检查失败不补造零值或支持能力',async()=>{
    const wrapper=mountReport(undefined)
    await wrapper.setProps({report:undefined})
    expect(wrapper.text()).toContain('尚无可核对的协议能力观测')
    for(const state of ['pending','unavailable'] as const){
      await wrapper.setProps({report:{schema_version:1,state,source:'unavailable',capture_active:false,observed_at:'2026-10-14T00:00:00Z',error_code:'inspection_pending',protocols:[],limits:[]}})
      expect(wrapper.text()).toContain('正在核对')
      expect(wrapper.find('.ant-table-wrapper').exists()).toBe(false)
    }
    await wrapper.setProps({report:{...sample(),schema_version:2}})
    expect(wrapper.text()).toContain('尚无可核对')
  })
  it('离线、停止或配置摘要变化明确提示，父观测变化关闭旧详情',async()=>{
    const wrapper=mountReport()
    await wrapper.get('button[aria-label="查看 TCP 协议能力"]').trigger('click');await flushPromises()
    expect(document.body.textContent).toContain('不适用应用层解析器配置')
    await wrapper.setProps({report:{...sample(),source:'offline_template',capture_active:false}});await flushPromises()
    expect(wrapper.text()).toContain('不能确认外部 EVE 生产进程')
    await wrapper.setProps({report:{...sample(),capture_active:false}})
    expect(wrapper.text()).toContain('未确认托管检测进程')
    await wrapper.setProps({report:sample(),capture:{interfaces:[],status:'running',config_sha256:'c'.repeat(64)}})
    expect(wrapper.text()).toContain('当前采集配置与此观测摘要不一致')
    await wrapper.get('input[aria-label="筛选协议"]').setValue('没有此协议')
    expect(wrapper.text()).toContain('没有匹配的协议')
    await wrapper.get('summary').trigger('click')
    expect(wrapper.text()).toContain('未在此配置中显式设置')
    expect(wrapper.text()).toContain('HTTP 站点专用配置可能覆盖')
  })
  it('共享弹窗提供关闭事件与明确目标名称',async()=>{
    const wrapper=mount(ProtocolCapabilitiesDialog,{props:{open:true,name:'站点采集器',report:sample(),refreshable:true},attachTo:document.body,global:{plugins:[registerAnt]}})
    await flushPromises();expect(document.body.textContent).toContain('协议能力 · 站点采集器')
    Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find(button=>button.textContent==='刷新观测')!.click();await flushPromises();expect(wrapper.emitted('refresh')).toHaveLength(1)
    document.querySelector<HTMLButtonElement>('.ant-modal-close')!.click();await flushPromises()
    expect(wrapper.emitted('close')).toHaveLength(1)
  })
  it('首次读取中及失败与未上报分开，保留刷新重试入口',async()=>{
    const wrapper=mount(ProtocolCapabilitiesDialog,{props:{open:true,loading:true,refreshable:true},attachTo:document.body,global:{plugins:[registerAnt]}})
    await flushPromises();expect(document.body.textContent).toContain('正在读取协议能力观测')
    expect(document.body.textContent).not.toContain('旧采集器可能尚未上报')
    await wrapper.setProps({loading:false,error:'状态服务读取超时'})
    expect(document.body.textContent).toContain('协议能力读取失败');expect(document.body.textContent).toContain('状态服务读取超时')
    expect(document.body.textContent).toContain('不能据此判断采集器是否上报协议能力')
    expect(wrapper.findComponent(ProtocolCapabilities).exists()).toBe(false)
    Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find(button=>button.textContent==='刷新观测')!.click();await flushPromises()
    expect(wrapper.emitted('refresh')).toHaveLength(1)
    await wrapper.setProps({error:'',report:sample()});expect(wrapper.getComponent(ProtocolCapabilities).props('report')).toEqual(sample())
    expect(document.body.textContent).toContain('HTTP/1');expect(document.body.textContent).not.toContain('状态服务读取超时')
    wrapper.unmount()
  })
  it('刷新中及失败保留已有协议和观测时间，不退回尚未上报提示',async()=>{
    const observed=sample(),wrapper=mount(ProtocolCapabilitiesDialog,{props:{open:true,report:observed,refreshable:true},attachTo:document.body,global:{plugins:[registerAnt]}})
    await flushPromises();const content=wrapper.getComponent(ProtocolCapabilities)
    await wrapper.setProps({loading:true});expect(wrapper.getComponent(ProtocolCapabilities).element).toBe(content.element)
    await wrapper.setProps({loading:false,error:'采集配置读取超时'})
    expect(document.body.textContent).toContain('刷新失败，保留上次观测')
    expect(document.body.textContent).toContain('HTTP/1');expect(document.body.textContent).not.toContain('旧采集器可能尚未上报')
    expect(wrapper.getComponent(ProtocolCapabilities).props('report')).toEqual(observed)
    wrapper.unmount()
  })
})

describe('协议能力响应完整性',()=>{
  it('接受固定版本的显式事实及失败观测，拒绝自报效果和畸形材料',()=>{
    expect(isProtocolReport(sample())).toBe(true)
    expect(isProtocolReport({...sample(),source:'offline_template',capture_active:false})).toBe(true)
    const mutations:((r:Record<string,any>)=>void)[]=[
      r=>{r.schema_version=2},r=>{r.observed_at='bad'},r=>{r.capture_active='yes'},r=>{r.protocols=Array(161).fill(r.protocols[0])},r=>{r.limits=Array(8).fill(r.limits[0])},
      r=>{r.state='accepted'},r=>{r.engine_version='8.0.70'},r=>{r.engine_sha256='bad'},r=>{r.config_sha256='bad'},r=>{r.source='other'},r=>{r.source='offline_template'},r=>{r.error_code='private'},r=>{r.protocols=[]},r=>{r.limits=[]},
      r=>{r.protocols[0].protocol='BAD'},r=>{r.protocols.push(r.protocols[0])},r=>{r.protocols[0].name=''},r=>{r.protocols[0].name='x\nprivate'},r=>{r.protocols[0].name='测'.repeat(22)},
      r=>{r.protocols[0].native_listed='yes'},r=>{r.protocols[0].file_extraction='configured'},r=>{r.protocols[0].external_logs='configured'},r=>{r.protocols[0].qualification='passed'},
      r=>{r.protocols[0].bindings=Array(3).fill({transport:'tcp',mode:'yes'})},r=>{r.protocols[0].bindings=[{transport:'other',mode:'yes'}]},r=>{r.protocols[0].bindings=[{transport:'tcp',mode:'other'}]},r=>{r.protocols[0].bindings.push({transport:'tcp',mode:'no'})},
      ...['recognition','transactions','online_rules','packet_forensics'].map(key=>(r:Record<string,any>)=>{r.protocols[0][key]='passed'}),
      r=>{r.limits[0].key='private.key'},r=>{r.limits[0]=r.limits[1]},r=>{r.limits[0].value='private-data'},
    ]
    for(const change of mutations){const r=structuredClone(sample());change(r);expect(isProtocolReport(r)).toBe(false)}
    for(const value of [null,[],{},false,'private'])expect(isProtocolReport(value)).toBe(false)
    const failure={schema_version:1,state:'unavailable',source:'unavailable',capture_active:false,observed_at:'2026-10-14T00:00:00Z',error_code:'engine_version_mismatch',protocols:[],limits:[]}
    expect(isProtocolReport(failure)).toBe(true)
    expect(isProtocolReport({...failure,engine_version:'8.0.7'})).toBe(false)
    expect(isProtocolReport({...failure,error_code:'private-data'})).toBe(false)
  })
})
