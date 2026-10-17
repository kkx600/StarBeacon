<script setup lang="ts">
import {onScopeDispose,ref,shallowRef,watch} from 'vue'
import {useRouter} from 'vue-router'
import {session} from '../../session'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {continuousStates,continuousCodes,validContinuousRecord,type ContinuousRecord} from './continuousDecisions'
import type {EvaluationRecord} from './decisionEvaluations'
const props=defineProps<{record:EvaluationRecord}>(),router=useRouter(),item=shallowRef<ContinuousRecord|null>(null),pending=ref(false),error=ref('')
let read:AbortController|undefined,stopped=false
async function load(){
 if(stopped)return
 read?.abort();const c=new AbortController();read=c;pending.value=true;error.value='';item.value=null
 const e=props.record,u=session.current.value
 try{
  if(!u)throw new Error('登录状态已失效，请重新登录。')
  const result=await session.api.request<unknown>('/decision-evaluations/'+encodeURIComponent(e.id)+'/continuous',{signal:c.signal})
  if(c.signal.aborted)return
  if(!result||typeof result!=='object'||Object.keys(result).length!==1||!('item' in result)||result.item!==null&&!await validContinuousRecord(result.item,e,u.tenant_id,u.id))throw new Error('持续决策档案与原评估或摘要不一致，请重试。')
  if(!c.signal.aborted)item.value=result.item as ContinuousRecord|null
 }catch(e){if(!c.signal.aborted)error.value=e instanceof Error?e.message:'持续决策记录读取失败。'}finally{if(read===c)pending.value=false}
}
watch(()=>[props.record.id,props.record.sha256,session.current.value?.id,session.current.value?.tenant_id],load,{immediate:true})
onScopeDispose(()=>{stopped=true;read?.abort()})
</script>
<template>
 <section class="continuous-panel" aria-label="持续决策授权记录">
  <div class="continuous-heading"><h3>持续决策授权</h3><a-button size="small" :loading="pending" @click="load">刷新授权记录</a-button></div>
  <StatePanel :loading="pending" :error="error" @retry="load">
   <template v-if="item"><a-alert :type="item.state==='queued'?'success':item.state==='skipped'?'warning':'info'" show-icon :message="continuousStates[item.state]+' · '+continuousCodes[item.code]" class="section-gap"/>
    <dl class="continuous-detail"><dt>记录标识</dt><dd class="technical">{{item.id}}</dd><dt>策略维护者</dt><dd>{{item.created_by}}</dd><dt>模型 / 修订</dt><dd>{{item.config.provider_id}} / {{item.config.provider_revision}}</dd><dt>记录 / 保留截止</dt><dd>{{formatTime(item.created_at)}} / {{formatTime(item.expires_at)}}</dd><template v-if="item.config.automatic"><dt>执行探针 / 设备</dt><dd>{{item.config.automatic.sensor_id}} / {{item.config.automatic.connector_id}}</dd><dt>探针注册代次</dt><dd class="technical">{{item.config.automatic.registration_id}}</dd><dt>设备配置 SHA-256</dt><dd class="technical">{{item.config.automatic.config_sha256}}</dd><dt>期限 / 冷却时间</dt><dd>{{item.config.automatic.ttl_seconds}} / {{item.config.automatic.cooldown_seconds}} 秒</dd><dt>每小时授权上限</dt><dd>{{item.config.automatic.max_hourly_actions}} 次</dd><dt>未校准分数授权</dt><dd>策略维护者已明确确认；仍须满足固定事实条件</dd></template><dt>授权档案 SHA-256</dt><dd class="technical">{{item.sha256}}</dd></dl>
    <a-button v-if="item.task_id" type="primary" @click="router.push({path:'/sensors',query:{view:'tasks',task:item.task_id}})">查看任务记录</a-button>
    <p class="page-description">签名任务受理、设备配置回读和实际流量效果需分别核对。该档案不把模型分数认定为已校准概率。</p>
   </template>
   <p v-else class="page-description">该评估没有持续决策授权记录。按需评估不触发自动执行；持续模式仅处理启用后创建并完成的本人指定模型研判。</p>
  </StatePanel>
 </section>
</template>
<style scoped>.continuous-panel{margin:12px 0;padding:12px;border:1px solid var(--line);border-radius:8px}.continuous-heading{display:flex;align-items:center;justify-content:space-between;gap:8px}.continuous-heading h3{margin:0}.continuous-detail{display:grid;grid-template-columns:140px minmax(0,1fr);gap:8px}.continuous-detail dd{margin:0;overflow-wrap:anywhere}.continuous-detail dt{color:var(--muted)}</style>
