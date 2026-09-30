import {reactive} from 'vue'
import {collectorDevice,createCollectorFixtures} from '../data/collector.ts'
import type {CollectorAction,CollectorTask} from '../data/collector'
const state=reactive(createCollectorFixtures())
let sequence=3
export function useCollector(){
  function request(action:CollectorAction,target:string,summary:string){
    const names:Record<CollectorAction,string>={network:'管理网络变更',capture:'采集配置变更',connection:'平台接入配置',enroll:'设备注册',certificate:'证书轮换', 'rule-sync':'规则同步','sync-settings':'规则同步配置',upgrade:'系统升级',rollback:'规则回滚',maintenance:'时间与存储配置',service:'服务维护',diagnostic:'诊断包生成'}
    const task:CollectorTask={id:`LOCAL-${String(sequence++).padStart(4,'0')}`,name:names[action],type:names[action],source:'本地管理员（示例）',target,status:'等待执行回执',time:'2026-09-30 09:48:00',summary,steps:[{name:'输入格式检查',status:'通过（本地）'},{name:'设备能力与授权检查',status:'待执行'},{name:'应用与执行回执',status:'尚未提供'},{name:'实际状态回读',status:'尚未提供'}]}
    state.tasks.unshift(task)
    state.audits.unshift({id:`AUD-${String(sequence).padStart(3,'0')}`,time:task.time,actor:task.source,action:task.name,object:target,result:'已创建本地申请，未执行'})
    return task
  }
  return {state,device:collectorDevice,request}
}
