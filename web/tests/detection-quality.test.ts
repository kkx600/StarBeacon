import {describe, expect, it, vi} from 'vitest'
import {flushPromises, mount} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import type {CaptureConfig} from '../packages/shared/src/types'
import {qualityCounters, qualityDisplayState, readQuality} from '../packages/shared/src/detectionQuality'
import type {QualityCounterKey, QualityReport} from '../packages/shared/src/detectionQuality'
import DetectionQuality from '../packages/shared/src/components/DetectionQuality.vue'
import DetectionQualityDialog from '../packages/shared/src/components/DetectionQualityDialog.vue'

function report(): QualityReport {
  const now = Date.now(), facet = () => ({state:'no_reported_change' as const, reasons:[]})
  return {schema_version:1,scope:'sensor_interval',source:'suricata_eve_stats',state:'observed',engine_run_id:'engine_quality',config_sha256:'b'.repeat(64),evaluated_at:new Date(now).toISOString(),sampled_at:new Date(now-1000).toISOString(),received_at:new Date(now-500).toISOString(),interval_started_at:new Date(now-6000).toISOString(),reset_counters:[],
    counters:Object.entries(qualityCounters).map(([key, [,layer,kind]])=>({key:key as QualityCounterKey,layer,kind,total:key==='decoder.bytes'?'18446744073709551615':key==='flow.active'?'9':'0',...(kind==='counter'?{delta:'0'}:{})})), capture:facet(),inspection:facet(),alerting:facet(),policy:facet()}
}
function capture(value=report()): CaptureConfig {return {interfaces:['eth0'],status:'running',managed:true,config_sha256:'b'.repeat(64),quality:value}}
const global = {plugins:[registerAnt]}

describe('检测质量回执边界', () => {
  it('核对配置、运行身份、唯一指标、整数精度和状态，不把损坏回执视为正常', () => {
    expect(readQuality(report(), 'b'.repeat(64))).not.toBeNull()
    expect(readQuality(report(), 'c'.repeat(64))).toBeNull()
    const changes: ((r:Record<string,any>)=>void)[] = [
      r=>{r.schema_version=2},r=>{r.scope='flow'},r=>{r.source='replay'},r=>{r.state='safe'},r=>{r.state='offline'},r=>{r.engine_run_id=null},r=>{r.engine_run_id='bad'},r=>{r.config_sha256='bad'},r=>{r.evaluated_at='bad'},
      r=>{r.counters=null},r=>{r.counters.pop()},r=>{r.counters[0]=null},r=>{r.counters[0].key='private'},r=>{r.counters[1]=r.counters[0]},r=>{r.counters[0].layer='policy'},r=>{r.counters[0].kind='gauge'},
      r=>{r.counters[0].total='18446744073709551616'},r=>{r.counters[0].total='01'},r=>{r.counters[0].total=null},r=>{r.counters[0].delta='-1'},r=>{r.counters[0].delta='1'},r=>{delete r.counters[0].total},r=>{r.counters[5].delta='0'},
      r=>{r.sampled_at='bad'},r=>{delete r.sampled_at},r=>{r.received_at='bad'},r=>{r.interval_started_at='bad'},r=>{r.interval_started_at=r.sampled_at},r=>{r.interval_started_at=new Date(Date.parse(r.sampled_at)-21000).toISOString()},
      r=>{r.reset_counters=null},r=>{r.reset_counters=['private']},r=>{r.reset_counters=['decoder.pkts','decoder.pkts']},r=>{r.capture=null},r=>{r.capture.state='safe'},r=>{r.capture.reasons=['detect.alert']},r=>{r.capture.reasons=Array(26).fill('capture.errors')},r=>{r.capture.reasons=null},r=>{r.state='baseline'},
    ]
    for (const change of changes) {const r=structuredClone(report());change(r);expect(readQuality(r, 'b'.repeat(64))).toBeNull()}
    for (const value of [undefined,null,[],false,'private',{}]) expect(readQuality(value)).toBeNull()
    const missing=report();missing.counters=missing.counters.map(row=>({key:row.key,layer:row.layer,kind:row.kind}));missing.capture.state='unknown';expect(readQuality(missing,missing.config_sha256)).not.toBeNull()
  })
  it('本地时钟、离线和停止状态均不能保留新鲜的区间结论', () => {
    const r=report(), now=Date.now()
    expect(qualityDisplayState(r,true,true,now)).toBe('observed')
    expect(qualityDisplayState(r,false,true,now)).toBe('stopped')
    expect(qualityDisplayState(r,true,false,now)).toBe('offline')
    expect(qualityDisplayState(r,true,true,now+21000)).toBe('stale')
    expect(qualityDisplayState(r,true,true,now-7000)).toBe('stale')
    r.sampled_at=new Date(now).toISOString();r.evaluated_at=new Date(now-21000).toISOString();expect(qualityDisplayState(r,true,true,now)).toBe('stale')
    r.evaluated_at=new Date(now+7000).toISOString();expect(qualityDisplayState(r,true,true,now)).toBe('stale')
    delete r.sampled_at;r.evaluated_at=new Date(now).toISOString();r.state='unavailable';expect(qualityDisplayState(r,true,true,now)).toBe('unavailable')
  })
})

describe('检测质量交互', () => {
  it('仅有一张指标表，独立呈现策略与损失，完整大数和字节单位可读', async () => {
    const r=report();r.counters[1]!.total='9007199254740993';r.counters[1]!.delta='2';r.counters[4]!.delta='1024';r.counters[22]!.total='1';r.counters[22]!.delta='1';r.capture={state:'limited',reasons:['capture.kernel_drops']};r.policy={state:'policy_applied',reasons:['detect.alerts_suppressed']}
    const wrapper=mount(DetectionQuality,{props:{capture:capture(r)},global})
    expect(wrapper.findAll('.ant-table-wrapper')).toHaveLength(1)
    expect(wrapper.text()).toContain('存在覆盖限制');expect(wrapper.text()).toContain('存在策略影响');expect(wrapper.text()).toContain('9,007,199,254,740,993');expect(wrapper.text()).toContain('18.45 EB');expect(wrapper.text()).toContain('1.02 KB');expect(wrapper.text()).toContain('瞬时值，不计算增量');expect(wrapper.text()).not.toContain('检测正常')
    const partial=report();delete partial.counters[1]!.total;delete partial.counters[1]!.delta;await wrapper.setProps({capture:capture(partial)});expect(wrapper.text()).toContain('未提供')
  })
  it('缺测、复位、采样断档和后台停留不补零或保留质量结论', async () => {
    vi.useFakeTimers();const wrapper=mount(DetectionQuality,{global})
    expect(wrapper.text()).toContain('尚未观测');expect(wrapper.find('.ant-table-wrapper').exists()).toBe(false)
    for (const state of ['baseline','counter_reset','sample_gap','stale','stopped'] as const) {
      const r=report();r.state=state;r.counters=r.counters.map(row=>({key:row.key,layer:row.layer,kind:row.kind,total:row.total}));r.capture.state=r.inspection.state=r.alerting.state=r.policy.state='unknown';if(state==='counter_reset')r.reset_counters=['detect.alert_queue_overflow']
      await wrapper.setProps({capture:capture(r)});expect(wrapper.text()).toContain('质量未知');expect(wrapper.text()).toContain('不可比较')
      if(state==='counter_reset')expect(wrapper.text()).toContain('复位指标')
    }
    await wrapper.setProps({capture:capture()});expect(wrapper.text()).toContain('区间观测')
    await vi.advanceTimersByTimeAsync(21000);expect(wrapper.text()).toContain('观测已过期');expect(wrapper.text()).toContain('不可比较')
    await wrapper.setProps({capture:capture(),online:false});expect(wrapper.text()).toContain('探针离线');expect(wrapper.text()).toContain('无法确认引擎是否运行');expect(wrapper.text()).not.toContain('引擎未运行')
    wrapper.unmount();expect(vi.getTimerCount()).toBe(0)
  })
  it('弹窗有刷新与关闭入口，关闭后不遗留采样时钟', async () => {
    const wrapper=mount(DetectionQualityDialog,{props:{open:true,capture:capture(),refreshable:true},global,attachTo:document.body});await flushPromises()
    await wrapper.setProps({error:'读取超时'});expect(document.body.textContent).toContain('刷新失败，保留上次观测');expect(document.body.textContent).toContain('请重试刷新观测');await wrapper.setProps({error:''})
    const button=(name:string)=>[...document.body.querySelectorAll<HTMLButtonElement>('button')].find(row=>row.textContent?.replace(/\s/g,'')===name)!
    button('刷新观测').click();await flushPromises();expect(wrapper.emitted('refresh')).toHaveLength(1)
    button('关闭').click();await flushPromises();document.querySelector<HTMLButtonElement>('.ant-modal-close')!.click();await flushPromises();expect(wrapper.emitted('close')).toHaveLength(2)
    await wrapper.setProps({open:false});await flushPromises();expect(wrapper.findComponent(DetectionQuality).exists()).toBe(false)
  })
})
