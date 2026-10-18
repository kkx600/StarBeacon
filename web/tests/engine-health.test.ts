import {describe,it,expect} from 'vitest'
import {mount} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import {readEngineHealth,engineHealthReason,type EngineHealth} from '../packages/shared/src/engineHealth'
import EngineHealthSummary from '../packages/shared/src/components/EngineHealthSummary.vue'
import HealthSummary from '../collector/src/features/network/HealthSummary.vue'
import type {HostHealth} from '../packages/shared/src/types'
const health:HostHealth={version:'0.1.0',hostname:'collector',observed_at:'2026-10-18T08:30:00Z',cpu_percent:10,memory_percent:20,disk_percent:30,rx_bytes:'100',tx_bytes:'200',wal_pending:0,wal_bytes:0,errors:[],capture_status:'running'}
const report:EngineHealth={schema_version:'1',state:'observed',source:'managed_process',observed_at:'2026-10-18T08:30:00Z',pid:125,started_at:'2026-10-18T08:00:00Z',config_sha256:'a'.repeat(64),rules_sha256:'b'.repeat(64),file_rule_count:12,rules_loaded:12,rules_failed:0}
describe('原生进程与规则装载观测',()=>{
 it('拒绝不完整、错误装载和未知形状，文件摘要不能代替原生观测',()=>{
  expect(readEngineHealth(report)).toEqual(report)
  for(const invalid of [null,[],{}, {...report,schema_version:'2'},{...report,state:'other'},{...report,observed_at:'bad'},{...report,rules_failed:-1},{...report,rules_failed:1.5},{...report,code:5},{...report,code:'error'},{...report,source:'eve_reader_only'},{...report,pid:0},{...report,pid:1.5},{...report,started_at:'bad'},{...report,started_at:'2026-10-19T00:00:00Z'},{...report,config_sha256:'missing'},{...report,rules_sha256:''},{...report,file_rule_count:0},{...report,file_rule_count:1.5},{...report,rules_loaded:11},{...report,rules_failed:1}])expect(readEngineHealth(invalid)).toBeNull()
  expect(readEngineHealth({...report,source:'registered_process'})).not.toBeNull()
  expect(readEngineHealth({schema_version:'1',state:'pending',source:'unavailable',observed_at:report.observed_at,rules_failed:0,code:'rule_operation_in_progress'})).not.toBeNull()
  expect(engineHealthReason(undefined)).toContain('观测时间');expect(engineHealthReason('unknown')).toContain('无法识别')
 })
 it('缺报和格式错误不显示成功；最新失败不保留旧进程及计数',async()=>{
  const wrapper=mount(EngineHealthSummary,{global:{plugins:[registerAnt]}})
  expect(wrapper.text()).toContain('尚无原生观测');expect(wrapper.text()).toContain('不能代替');expect(wrapper.find('.ant-descriptions').exists()).toBe(false)
  await wrapper.setProps({report:{state:'observed'}});expect(wrapper.text()).toContain('格式不完整');expect(wrapper.text()).not.toContain('最近观测通过')
  await wrapper.setProps({report});expect(wrapper.text()).toContain('最近观测通过');expect(wrapper.text()).toContain('托管检测进程');expect(wrapper.text()).toContain('PID 125');expect(wrapper.text()).toContain('已装载 12 条 / 文件 12 条');expect(wrapper.text()).toContain('不证明引擎内存中的规则内容相同');expect(wrapper.find('.ant-tag-success').exists()).toBe(true)
  await wrapper.setProps({report:{...report,source:'registered_process'}});expect(wrapper.text()).toContain('登记检测进程')
  await wrapper.setProps({report:{...report,state:'unavailable',code:'engine_process_unverified'}});expect(wrapper.text()).toContain('无法核实登记进程');expect(wrapper.text()).not.toContain('PID 125');expect(wrapper.find('.ant-descriptions').exists()).toBe(false);expect(wrapper.find('.ant-tag-error').exists()).toBe(true)
  await wrapper.setProps({report:{...report,state:'pending',code:'rule_operation_in_progress'}});expect(wrapper.text()).toContain('等待原生观测');expect(wrapper.text()).toContain('重新核对')
  await wrapper.setProps({report:{...report,state:'unconfigured',code:'engine_observation_not_configured'}});expect(wrapper.text()).toContain('未配置原生观测');expect(wrapper.text()).toContain('未登记完整')
  wrapper.unmount()
 })
 it('采集器运行页面展示同一原生观测组件',()=>{
  const wrapper=mount(HealthSummary,{global:{plugins:[registerAnt]},props:{health:{...health,engine_health:report}}})
  expect(wrapper.text()).toContain('检测引擎观测');expect(wrapper.text()).toContain('已装载 12 条');wrapper.unmount()
 })
})
