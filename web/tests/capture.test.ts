import {describe,expect,it} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {Checkbox,InputNumber,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {CaptureConfig} from '../packages/shared/src/types'
import CaptureForm from '../packages/shared/src/components/CaptureForm.vue'
const iface={name:'eth0',index:1,mac:'02:00:00:00:00:01',mtu:1500,up:true,loopback:false,addresses:['192.0.2.1/24']}
const running:CaptureConfig={interfaces:['eth0'],threads:2,bpf_filter:'tcp port 80',promiscuous:false,managed:true,status:'running',revision:2,applied_revision:2,applied_settings:{interfaces:['eth0'],threads:2,bpf_filter:'tcp port 80',promiscuous:false},observed_at:'2026-10-03T01:00:00Z'}
function form(capture:CaptureConfig=running){return mount(CaptureForm,{props:{interfaces:[iface],capture,saving:false},global:{plugins:[registerAnt]}})}
async function submit(wrapper:ReturnType<typeof form>){await wrapper.get('form').trigger('submit');await flushPromises()}

describe('采集配置与实际状态',()=>{
 it('状态和计数通过真实描述组件呈现业务标签',()=>{
  const wrapper=form({...running,counters:{'decoder.bytes':'2048','capture.kernel_drops':'0'},counters_observed_at:running.observed_at,spool_bytes:'1024',spool_budget:'1073741824'})
  expect(wrapper.find('a-descriptions').exists()).toBe(false);expect(wrapper.find('a-descriptions-item').exists()).toBe(false)
  const labels=wrapper.findAll('.ant-descriptions-item-label').map(item=>item.text())
  expect(labels).toEqual(expect.arrayContaining(['实际状态','生效网卡','配置修订','观测时间','引擎累计流量','内核丢包','计数观测时间','EVE 缓冲占用']))
 })
 it('提交独立网卡、线程、混杂与过滤参数，计数刷新保留编辑草稿',async()=>{
  const wrapper=form();expect(wrapper.text()).toContain('采集中');expect(wrapper.text()).toContain('期望 2 / 生效 2')
  await wrapper.get('input[aria-label="BPF 捕获过滤器"]').setValue('  tcp port 8088  ')
  await wrapper.setProps({capture:{...running,counters:{'decoder.bytes':'18446744073709551615','capture.kernel_drops':'3'},counters_observed_at:running.observed_at,spool_bytes:'1048576',spool_budget:'1073741824',rotation_pending:true}});expect(wrapper.text()).toContain('18.45 EB');expect(wrapper.text()).toContain('1.05 MB / 1.07 GB');expect(wrapper.text()).toContain('持久排空');expect(wrapper.get<HTMLInputElement>('input[aria-label="BPF 捕获过滤器"]').element.value).toContain('8088')
  await submit(wrapper);expect(wrapper.emitted('save')?.[0]?.[0]).toEqual({interfaces:['eth0'],threads:2,bpf_filter:'tcp port 8088',promiscuous:false})
  await wrapper.setProps({capture:{...running,revision:3,bpf_filter:'udp port 53'}});expect(wrapper.get<HTMLInputElement>('input[aria-label="BPF 捕获过滤器"]').element.value).toBe('udp port 53')
 })
 it('实际配置失败保留生效网卡与原修订，缺失计数不显示为零',()=>{
  const wrapper=form({...running,interfaces:['missing'],status:'degraded',revision:3,error_code:'capture_filter_invalid',counters:{}})
  expect(wrapper.text()).toContain('运行异常');expect(wrapper.text()).toContain('目标配置未生效');expect(wrapper.text()).toContain('期望 3 / 生效 2');expect(wrapper.text()).toContain('尚未观测');expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
 })
 it('停止当前采集必须明确确认，停止后空目标不伪装为捕获成功',async()=>{
  const wrapper=form();await wrapper.getComponent(Select).setValue([],'value');await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined();expect(wrapper.text()).toContain('确认停止当前采集')
  const checks=wrapper.findAllComponents(Checkbox);await checks.at(-1)!.setValue(true,'checked');await submit(wrapper);expect(wrapper.emitted('save')?.[0]?.[0]).toMatchObject({interfaces:[]})
  await wrapper.setProps({capture:{interfaces:[],status:'stopped',managed:true,revision:3,applied_revision:3,applied_settings:{interfaces:[]}}});expect(wrapper.text()).toContain('未采集');expect(wrapper.text()).not.toContain('确认停止当前采集');expect(wrapper.text()).toContain('已停止')
 })
 it('不可信输入与等待中的保存不能重复提交',async()=>{
  const wrapper=form();const number=wrapper.getComponent(InputNumber)
  for(const value of [0,65,2.5,null]){await number.setValue(value,'value');await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined()}
  await number.setValue(1,'value');await wrapper.get('input[aria-label="BPF 捕获过滤器"]').setValue('x'.repeat(2049));await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined()
  await wrapper.get('input[aria-label="BPF 捕获过滤器"]').setValue('tcp port 80');await wrapper.setProps({saving:true});await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined();expect(wrapper.getComponent(Select).props('disabled')).toBe(true)
 })
 it('总线程数与已关闭接口约束适用于所有所选网卡',async()=>{
  const wrapper=form();const interfaces=[iface,{...iface,name:'eth1'},{...iface,name:'eth2'}];await wrapper.setProps({interfaces});await wrapper.getComponent(Select).setValue(['eth0','eth1','eth2'],'value');await wrapper.getComponent(InputNumber).setValue(64,'value');await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined()
  await wrapper.getComponent(InputNumber).setValue(1,'value');await wrapper.setProps({interfaces:interfaces.map(i=>({...i,up:false}))});await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined()
 })
 it('未知错误保留业务提示，外部 EVE 模式不声明已生效',()=>{
  const unknown=form({...running,status:'failed',error_code:'unrecognized'});expect(unknown.text()).toContain('实际采集状态需要核对')
  const external=form({interfaces:[],status:'not_applied'});expect(external.text()).toContain('外部 EVE 文件');expect(external.text()).toContain('保存采集目标');expect(external.text()).not.toContain('期望 2')
 })
 it('非 Ethernet 接口、重复目标和 UTF-8 过滤器超限不提交',async()=>{
  const wrapper=form();await wrapper.setProps({interfaces:[iface,{...iface,name:'tunnel0',mac:''},{...iface,name:'ib0',mac:'01:02:03:04:05:06:07:08'}]})
  expect(wrapper.getComponent(Select).props('options')).toMatchObject([{disabled:false},{disabled:true},{disabled:true}])
  for(const names of [['tunnel0'],['eth0','eth0']]){await wrapper.getComponent(Select).setValue(names,'value');await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined()}
  await wrapper.getComponent(Select).setValue(['eth0'],'value');await wrapper.get('input[aria-label="BPF 捕获过滤器"]').setValue('测'.repeat(700));await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined()
 })
})
