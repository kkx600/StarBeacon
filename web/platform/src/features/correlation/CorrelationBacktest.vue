<script setup lang="ts">
import {onScopeDispose,shallowRef,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import CorrelationScopeForm from '@starbeacon/shared/components/CorrelationScopeForm.vue'
import CorrelationResultTable from '@starbeacon/shared/components/CorrelationResultTable.vue'
import {readCorrelationRule,readCorrelationResult,correlationRequestError,type CorrelationRule,type CorrelationRequest,type CorrelationResult} from '@starbeacon/shared/correlation.ts'
import {ApiError} from '@starbeacon/shared/api.ts'
import {formatTime} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
const route=useRoute(),router=useRouter(),rule=shallowRef<CorrelationRule|null>(null),loading=shallowRef(false),error=shallowRef(''),pending=shallowRef(false),runError=shallowRef(''),notice=shallowRef(''),result=shallowRef<CorrelationResult|null>(null)
let readController:AbortController|undefined,runController:AbortController|undefined,stopped=false
function clear(){result.value=null;runError.value='';notice.value=''}
function criteriaChanged(){runController?.abort();runController=undefined;pending.value=false;clear()}
function cancel(){runController?.abort();runController=undefined;pending.value=false;result.value=null;runError.value='';notice.value='已停止等待本次回测，迟到结果不会显示。'}
async function load(){
 readController?.abort();runController?.abort();runController=undefined;pending.value=false;rule.value=null;error.value='';clear()
 const id=route.query.rule_id,revision=route.query.revision
 if(id===undefined&&revision===undefined){loading.value=false;return}
 if(typeof id!=='string'||!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(id)||typeof revision!=='string'||!/^[1-9]\d{0,6}$/.test(revision)||Number(revision)>1000000){loading.value=false;error.value='规则选择参数无效，请返回目录选择固定修订。';return}
 const current=new AbortController();readController=current;loading.value=true
 try{const value=await session.api.request<unknown>(`/correlation-rules/${id}/revisions/${revision}`,{signal:current.signal});if(current.signal.aborted)return;const checked=await readCorrelationRule(value,session.current.value?.tenant_id??'');if(checked.id!==id||checked.revision!==Number(revision))throw new Error('规则修订与当前选择不一致。');if(!current.signal.aborted)rule.value=checked}catch(cause){if(!current.signal.aborted)error.value=cause instanceof Error?cause.message:'规则修订读取失败。'}finally{if(readController===current)loading.value=false}
}
async function run(query:CorrelationRequest){
 const selected=rule.value
 if(stopped||pending.value||!selected||!selected.active||query.expected_revision!==selected.revision)return
 const invalid=correlationRequestError(query);if(invalid){runError.value=invalid;return}
 runController?.abort();const current=new AbortController();runController=current;pending.value=true;clear()
 const submitted=structuredClone(query),timer=setTimeout(()=>current.abort(),55000)
 try{
  const value=await session.api.request<unknown>(`/correlation-rules/${selected.id}/backtest`,{method:'POST',body:submitted,signal:current.signal})
  if(stopped||runController!==current||current.signal.aborted)return
  const checked=await readCorrelationResult(value,selected,submitted)
  if(!stopped&&runController===current&&!current.signal.aborted)result.value=checked
 }catch(cause){if(!stopped&&runController===current){runError.value=current.signal.aborted?'回测等待超时，未展示部分结果，请稍后重试。':cause instanceof Error?cause.message:'回测未完成。';if(cause instanceof ApiError&&cause.status===409)notice.value='请返回规则目录核对当前状态与修订，再重新选择。'}}finally{clearTimeout(timer);if(runController===current)pending.value=false}
}
watch(()=>[route.query.rule_id,route.query.revision],()=>{void load()},{immediate:true})
onScopeDispose(()=>{stopped=true;readController?.abort();runController?.abort()})
</script>
<template>
 <header class="page-header"><div><h1>窗口回测</h1><p class="page-description">对固定告警快照计算窗口计数或不同值数量，逐项核对来源与证据。</p></div><a-button @click="router.push('/detection/correlation/rules')">返回规则目录</a-button></header>
 <a-alert type="info" show-icon message="回测只描述已经进入检索快照的告警。未观察到阈值不代表流量安全，来源覆盖尚未证明；结果不生成告警或设备处置。" class="section-gap"/>
 <StatePanel :loading="loading" :error="error" :empty="!rule" description="请从关联规则目录选择一条允许回测的规则，并指定固定修订。" @retry="load">
  <template v-if="rule"><section class="panel panel-body section-gap"><strong class="correlation-rule-name">{{rule.name}}</strong><span class="correlation-rule-caption">固定修订 {{rule.revision}} · {{rule.definition.window_seconds}} 秒窗口 · 阈值 {{rule.definition.threshold}}</span><p class="page-description">{{rule.definition.filter?'告警条件：'+rule.definition.filter:'所选范围内全部告警'}}。执行时重新核对当前规则状态与修订。</p><a-alert v-if="!rule.active" type="warning" show-icon message="所选修订已停用，请返回目录核对当前规则。"/></section>
   <CorrelationScopeForm :key="rule.id+'/'+rule.revision" :revision="rule.revision" :window-seconds="rule.definition.window_seconds" :pending="pending" :disabled="!rule.active" :error="runError" @run="run" @cancel="cancel" @change="criteriaChanged"/>
   <a-alert v-if="notice" type="info" show-icon :message="notice" class="section-gap"/>
   <section class="panel correlation-result"><div class="panel-header"><h2>回测结果</h2><span v-if="result">{{formatTime(result.observed_at)}}</span></div><StatePanel :loading="pending" :empty="!result" description="尚无当前条件的回测结果。单次最多读取 5000 条告警、512 个窗口分组，失败或超限不交付部分结果。"><template v-if="result"><CorrelationResultTable :result="result" :definition="rule.definition"/><p class="page-description correlation-result-footnote">结果仅保留在当前页面会话。快照 SHA-256：<span class="technical">{{result.snapshot_sha256}}</span></p></template></StatePanel></section>
  </template>
 </StatePanel>
</template>
<style scoped>.correlation-rule-name{overflow-wrap:anywhere}.correlation-rule-caption{display:inline-block;margin-left:12px}.correlation-result{margin-top:12px}.correlation-result-footnote{padding:0 16px 12px;overflow-wrap:anywhere}</style>
