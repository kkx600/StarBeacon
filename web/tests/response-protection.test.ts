import {describe,expect,it} from 'vitest'
import {mount} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import {validResponseProtection,type ResponseProtection} from '../packages/shared/src/responseProtection'
import ResponseProtectionSummary from '../packages/shared/src/components/ResponseProtectionSummary.vue'
import type {ResponseAction} from '../packages/shared/src/response'
import {validTask} from '../packages/shared/src/useTaskDetail'
import {principal,sensor} from './fixtures'

const now=Date.now()
const action:ResponseAction={schema_version:'response.action.v1',connector_id:'connector_owned',device_id:'device_owned',config_sha256:'a'.repeat(64),lease_id:'task_owned',owner_sha256:'b'.repeat(64),target_ip:'198.51.100.12',requested_at:new Date(now).toISOString(),expires_at:new Date(now+60000).toISOString(),reason:'受控限时处置'}
const proof=():ResponseProtection=>({schema_version:'response.protection.v1',command_sha256:'c'.repeat(64),check_sha256:'d'.repeat(64),check:{schema_version:'watchlist-response-check.v1',checked_at:new Date(now+10).toISOString(),state_sha256:'e'.repeat(64),matches:[]}})

describe('封禁授权名单核对记录',()=>{
 it('区分原任务授权与锁后核对时刻，并接受明确的历史缺失',()=>{
  expect(validResponseProtection(proof(),'response.block',action.requested_at,action.expires_at)).toBe(true)
  expect(validResponseProtection(undefined,'response.block',action.requested_at,action.expires_at)).toBe(true)
  for(const delta of [-30000,30000]){const value=proof();value.check.checked_at=new Date(now+delta).toISOString();expect(validResponseProtection(value,'response.block',action.requested_at,action.expires_at)).toBe(true)}
 })
 it('拒绝其他动作、损坏结构、错误摘要、命中项和越过授权时间的材料',()=>{
  for(const value of [null,[],{}, {...proof(),schema_version:'other'}, {...proof(),extra:true},{...proof(),command_sha256:'A'.repeat(64)},{...proof(),check_sha256:7},{...proof(),check:[]},{...proof(),check:{...proof().check,extra:1}},{...proof(),check:{...proof().check,schema_version:'other'}},{...proof(),check:{...proof().check,state_sha256:''}},{...proof(),check:{...proof().check,matches:null}},{...proof(),check:{...proof().check,matches:[{id:'protected'}]}},{...proof(),check:{...proof().check,checked_at:7}},{...proof(),check:{...proof().check,checked_at:'invalid'}}])expect(validResponseProtection(value,'response.block',action.requested_at,action.expires_at)).toBe(false)
  for(const delta of [-30001,30001,60000]){const value=proof();value.check.checked_at=new Date(now+delta).toISOString();expect(validResponseProtection(value,'response.block',action.requested_at,action.expires_at)).toBe(false)}
  expect(validResponseProtection(proof(),'response.read',action.requested_at,action.expires_at)).toBe(false)
  expect(validResponseProtection(proof(),'response.block','bad',action.expires_at)).toBe(false)
  expect(validResponseProtection(proof(),'response.block',action.requested_at,'bad')).toBe(false)
  expect(validResponseProtection(proof(),'response.block',action.requested_at,action.requested_at)).toBe(false)
 })
 it('实际详情显示冻结依据和后续变更边界，不创建第二张业务表',()=>{
  const value=proof(),w=mount(ResponseProtectionSummary,{props:{action,proof:value},global:{plugins:[registerAnt]}})
  expect(w.text()).toContain('平台授权时未命中有效保护名单')
  expect(w.text()).toContain('后续名单变更不自动撤销')
  expect(w.text()).toContain(value.check.state_sha256)
  expect(w.text()).toContain(value.command_sha256)
  expect(w.findAll('table')).toHaveLength(1)
 })
 it('旧任务和错误材料给出各自说明，不展示成功结论',()=>{
  const old=mount(ResponseProtectionSummary,{props:{action},global:{plugins:[registerAnt]}})
  expect(old.text()).toContain('没有名单核对记录')
  expect(old.text()).not.toContain('平台授权时未命中')
  const bad=mount(ResponseProtectionSummary,{props:{action,proof:{...proof(),check_sha256:'bad'}},global:{plugins:[registerAnt]}})
  expect(bad.text()).toContain('名单核对记录不完整')
  expect(bad.text()).not.toContain('平台授权时未命中')
 })
 it('任务读取拒绝将名单记录嫁接到其他类型或接受未完整返回的核对',()=>{
  const task={id:'task_owned',sensor_id:sensor.id,created_by:principal.id,kind:'response.block',state:'queued',created_at:action.requested_at,updated_at:action.requested_at,expires_at:action.expires_at,retain_until:new Date(now+180*86400000).toISOString(),delivery_count:0,receipt:{},response_action:action,response_protection:proof()}
  expect(validTask(task,task.id)).toBe(true)
  expect(validTask({...task,response_protection:{...proof(),schema_version:'other'}},task.id)).toBe(false)
  expect(validTask({...task,kind:'diagnostics'},task.id)).toBe(false)
  expect(validTask({...task,kind:'response.read'},task.id)).toBe(false)
 })
})
