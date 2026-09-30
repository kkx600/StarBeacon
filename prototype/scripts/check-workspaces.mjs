import assert from 'node:assert/strict'
import {pages,pageById as actualPageById} from '../src/data/catalog.ts'
import {workspaces,workspaceForPage,legacyPages} from '../src/data/navigation.ts'
import {createFixtures} from '../src/data/fixtures.ts'
import {healthFor,sensorMetrics,defaultSensorThresholds} from '../src/data/sensorHealth.ts'
import {formValueFor,expiryFromDuration} from '../src/composables/formValues.ts'

const pageById=new Map(pages.map(page=>[page.id,page]))
for(const [legacy,target] of Object.entries(legacyPages)){
  assert(!actualPageById.has(legacy),`${legacy} 不应留在渲染字典`)
  assert(!pageById.has(legacy),`${legacy} 不应继续创建独立数据集`)
  assert(pageById.has(target),`${legacy} 需要有效的兼容入口`)
}
assert.equal(workspaceForPage.get('models'),workspaceForPage.get('knowledge'))
assert.equal(workspaceForPage.get('pcap-tasks'),workspaceForPage.get('sessions'))
assert(workspaces.every(workspace=>workspace.pages.length<=7),'工作区不能形成无边界的页签集合')
for(const page of pages)for(const field of page.fields){
  if(field.type!=='select'||!field.options?.length||['name','status'].includes(field.key))continue
  for(const record of createFixtures(page))if(record[field.key]!=null)assert(field.options.includes(String(record[field.key])),`${page.id}.${field.key} 与业务选项不一致`)
}
assert.equal(formValueFor({key:'stream',label:'重组深度（MiB）',type:'number'}, {id:'TEST',name:'测试',status:'正常',stream:'8 MiB'}),8)
assert.equal(formValueFor({key:'timeout',label:'超时（秒）',type:'number'}, {id:'TEST',name:'测试',status:'正常',timeout:'180 秒'}),180)
assert.equal(formValueFor({key:'type',label:'报告周期',type:'select',options:['日报','周报','月报']}, {id:'TEST',name:'测试',status:'正常',type:'服务器'}),undefined,'未知选项不能静默映射为有效业务值')
assert.equal(expiryFromDuration('7 天','2026-09-30T09:45:00Z'),'2026-10-07 09:45:00')
assert.equal(expiryFromDuration('1 小时','2026-09-30T09:45:00Z'),'2026-09-30 10:45:00')
assert.equal(createFixtures(pageById.get('api-keys'))[0].expires,'2026-10-07 09:45:00')
assert.equal(createFixtures(pageById.get('roles'))[1].permissions,12)
const schedules=createFixtures(pageById.get('report-schedules'))
assert(schedules.some(record=>record.type==='周报'&&String(record.schedule).includes('每周一')))
assert(schedules.some(record=>record.type==='月报'&&String(record.schedule).includes('每月')))
const sensorPage=pageById.get('sensors')
assert.deepEqual(sensorPage.requirement,['SB-OPS-001','SB-OPS-002'])
const sensors=createFixtures(sensorPage)
assert.equal(new Set(sensors.map(record=>record.name)).size,sensors.length,'同一设备只能有一个列表身份')
for(const record of sensors){
  assert.equal(record.zone,record.scope)
  if(record.status==='离线')for(const field of ['cpu','memory','disk','bps','drop'])assert.equal(record[field],null,`离线遥测不能显示为当前 ${field}`)
}
const first=sensors[0]
assert.equal(healthFor({...first,heartbeatAge:181}),'不可观测')
assert.equal(healthFor({...first,cpu:80}),'CPU 负载高')
assert.equal(healthFor({...first,cpu:80},{...defaultSensorThresholds,cpu:90}),'正常')
assert.equal(healthFor({...first,dropPercent:0.1}),'丢包关注')
assert.equal(healthFor({...first,dropPercent:null}),'遥测不完整')
const execution=sensors.find(record=>record.role==='执行采集器')
for(const action of createFixtures(pageById.get('actions')))assert(sensors.some(sensor=>sensor.name===action.sensor&&sensor.role==='执行采集器'),'动作只能引用已登记的执行采集器')
assert.equal(sensorMetrics([execution],defaultSensorThresholds)[3].value,'—','执行角色不能叠加为捕获流量')
const offline=sensors.find(record=>record.status==='离线')
assert.equal(sensorMetrics([offline],defaultSensorThresholds)[1].value,'0')
assert.equal(sensorMetrics([offline],defaultSensorThresholds)[3].value,'—','没有捕获遥测时不能冒充零流量')
assert.equal(sensorMetrics([offline],defaultSensorThresholds)[2].value,'1')
assert.equal(sensorMetrics([],defaultSensorThresholds)[0].value,'0')
const pcaps=createFixtures(pageById.get('pcap-tasks'))
for(const record of pcaps.filter(record=>record.status==='可下载'&&record.mode==='完整会话')){
  assert(!/缺少|缺口|活动/.test(`${record.handshake} ${record.continuity} ${record.closure}`),'可下载完整会话不得存在已知完整性缺口')
  assert.equal(record.exportObject,null,'合成任务不能冒充真实 PCAP 对象')
}
console.log('工作区与数据边界核对通过：兼容入口、对象身份、业务选项、表单单位、报告周期、执行引用、遥测与 PCAP 完整性。')
