<script setup lang="ts">
import {computed,ref,watch,onScopeDispose} from 'vue'
import {Modal,Table,message} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {checkClass,resultNames} from '../models/models'
import {countText} from '../overview/overview'
import {analysisCodes,analysisFacts,kindNames,stateNames,totalAlerts,working,type AnalysisJob} from './analysis'
import {session} from '../../session'
const props=defineProps<{open:boolean;job:AnalysisJob|null;loading:boolean;error:string;busy:boolean}>()
const emit=defineEmits<{close:[];retry:[];cancel:[id:string]}>()
const exporting=ref(false)
let downloadControl:AbortController|undefined
watch(()=>props.open,open=>{if(!open)downloadControl?.abort()})
onScopeDispose(()=>downloadControl?.abort())
const facts=computed(()=>props.job?analysisFacts(props.job):[])
async function download(){if(!props.job||exporting.value)return;const control=new AbortController();downloadControl=control;exporting.value=true;try{const job=props.job,blob=await session.api.download('/analysis/jobs/'+encodeURIComponent(job.id)+'/report',control.signal);if(control.signal.aborted)return;const url=URL.createObjectURL(blob),link=document.createElement('a'),revoke=URL.revokeObjectURL.bind(URL);link.href=url;link.download=`starbeacon-${job.request.kind}-${job.request.period}-${job.id}.html`;link.click();setTimeout(()=>revoke(url),1000)}catch(e){if(!control.signal.aborted)message.error(e instanceof Error?e.message:'报告导出失败')}finally{exporting.value=false}}
</script>
<template>
 <Modal :open="open" :title="job?`${kindNames[job.request.kind]} · ${job.request.kind==='chat'?'分析记录':job.request.period}`:'分析结果'" :width="880" :footer="null" @cancel="emit('close')">
  <StatePanel :loading="loading&&!job" :error="!job?error:''" :empty="false" @retry="emit('retry')"><template v-if="job">
   <a-alert v-if="error" type="error" :message="`${error}。当前显示上次成功读取的结果。`" show-icon class="section-gap"/>
   <div class="filter-actions section-gap"><span :class="['status',checkClass(job.state)]">{{stateNames[job.state]??'其他处理状态'}}</span><span class="muted">修订 {{job.revision}} · {{formatTime(job.created_at)}}</span><a-button :loading="loading" :disabled="busy||loading" @click="emit('retry')">刷新结果</a-button><a-button v-if="working(job.state)" danger :disabled="busy||job.cancel_requested" @click="emit('cancel',job.id)">{{job.cancel_requested?'取消请求已提交':'取消分析'}}</a-button><a-button v-if="job.request.kind!=='chat'&&!working(job.state)" :loading="exporting" @click="download">导出 HTML</a-button></div>
   <p class="page-description section-gap">{{analysisCodes[job.result.code]??resultNames[job.result.code]??'尚未获取处理说明'}}。提供方受理和用量以实际返回为准。</p>
   <a-alert v-if="job.state==='uncertain'||job.cancel_requested&&working(job.state)" type="warning" message="请求可能已由提供方执行，取消不保证停止计费；未确认结果不会自动重试。" show-icon class="section-gap"/>
   <div class="analysis-statistics"><div><span>已索引告警</span><strong :title="totalAlerts(job)">{{countText(totalAlerts(job))}}</strong></div><div><span>登记资产（生成时）</span><strong>{{countText(job.evidence.segments.at(-1)?.inventory.assets??'0')}}</strong></div><div><span>在线探针（生成时）</span><strong>{{countText(job.evidence.segments.at(-1)?.inventory.online??'0')}}</strong></div></div>
   <p class="muted">统计范围：{{formatTime(job.evidence.window.start)}} — {{formatTime(job.evidence.window.end)}} · {{job.request.timezone||'UTC'}}</p>
   <section v-if="job.answer" class="analysis-narrative"><h2>模型概述</h2><p>{{job.answer.summary}}</p><template v-for="group in [{label:'统计观察',items:job.answer.observations},{label:'调查建议',items:job.answer.recommendations}]" :key="group.label"><h2>{{group.label}}</h2><p v-if="!group.items.length" class="muted">暂无内容</p><div v-for="(item,index) in group.items" :key="index"><p>{{item.text}}</p><small class="muted">来源：{{item.sources.join('、')}}</small></div></template></section>
   <a-alert v-else-if="!working(job.state)" type="info" message="智能总结不可用或未启用，完整统计来源仍可复核。" show-icon class="section-gap"/>
   <a-alert type="info" message="统计快照记录已索引告警；检测命中不代表攻击成功，登记状态不代表周期覆盖率。模型建议需要人工复核。" show-icon class="section-gap"/>
   <h2>统计来源</h2><div class="table-wrap"><Table :data-source="facts" :columns="[{title:'来源标识',dataIndex:'id',width:220},{title:'统计项',dataIndex:'label',width:240},{title:'统计值',dataIndex:'value',width:200}]" row-key="id" :pagination="{pageSize:10,showSizeChanger:false}" :scroll="{x:660}"/></div>
   <dl class="analysis-metadata"><dt>分析标识</dt><dd>{{job.id}}</dd><dt>输入 Token / 输出 Token / 总 Token</dt><dd>{{job.result.usage?`${job.result.usage.input_tokens} / ${job.result.usage.output_tokens} / ${job.result.usage.total_tokens}`:'未获取 / 未获取 / 未获取'}}</dd><dt>模型处理耗时</dt><dd>{{job.result.duration_ms==null?'未获取':`${job.result.duration_ms} ms`}}</dd><dt>模型标识</dt><dd>{{job.result.returned_model??(job.request.provider_id||'未调用模型')}}</dd><dt>快照 SHA-256</dt><dd>{{job.evidence.sha256}}</dd><dt>保留至</dt><dd>{{formatTime(job.expires_at)}}</dd></dl>
   <p v-for="limit in job.evidence.segments[0]?.limitations??[]" :key="limit" class="muted">{{limit}}</p>
  </template></StatePanel>
 </Modal>
</template>
<style scoped>.analysis-statistics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:12px 0}.analysis-statistics>div{display:grid;gap:4px;border:1px solid var(--line);border-top:3px solid var(--primary);padding:12px;background:#fff}.analysis-statistics span{color:var(--muted);font-size:12px}.analysis-statistics strong{font-size:24px;overflow-wrap:anywhere}.analysis-narrative p{white-space:pre-wrap;overflow-wrap:anywhere}.analysis-narrative>div{padding:8px 0;border-bottom:1px solid var(--line)}h2{font-size:16px;margin:12px 0 8px}.analysis-metadata{display:grid;grid-template-columns:minmax(150px,1fr) minmax(0,2fr);gap:8px;margin:12px 0}.analysis-metadata dt{color:var(--muted)}.analysis-metadata dd{margin:0;overflow-wrap:anywhere}@media(max-width:640px){.analysis-statistics{grid-template-columns:1fr}.analysis-metadata{grid-template-columns:1fr}}</style>
