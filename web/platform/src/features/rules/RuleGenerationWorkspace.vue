<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Checkbox as ACheckbox,Descriptions as ADescriptions,Modal as AModal,Radio as ARadio,Select as ASelect,Table as ATable,message} from 'ant-design-vue'
import type {ReplaySample,RulePackage} from '@starbeacon/shared/types.ts'
import type {ModelProvider} from '../models/models'
import {formatTime} from '@starbeacon/shared/types.ts'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import RuleEditor from '@starbeacon/shared/components/RuleEditor.vue'
import {session} from '../../session'
import {checkClass,resultNames} from '../models/models'
import {generationCodes,generationStates,generationWorking,sourceNames,validGenerationSample,type GenerationSource} from './generation'
import {useRuleGeneration} from './useRuleGeneration'
const ADescriptionsItem=ADescriptions.Item,ARadioGroup=ARadio.Group
const emit=defineEmits<{adopted:[value:RulePackage];samples:[]}>()
const generation=useRuleGeneration()
const {items,next,pending,error,available,selected,loading,detailError,busy,actionError,unconfirmed}=generation
const creating=shallowRef(false),viewing=shallowRef(false),optionsPending=shallowRef(false),optionsError=shallowRef(''),formError=shallowRef(''),chosenSID=shallowRef<number>(),adopted=shallowRef<RulePackage|null>(null)
const providers=shallowRef<ModelProvider[]>([]),samples=shallowRef<ReplaySample[]>([])
const form=reactive({description:'',source:'natural_language' as GenerationSource,provider_id:undefined as string|undefined,sample_id:undefined as string|undefined,candidate_count:1,allow_context:false})
const detailID=shallowRef('')
let stopped=false,optionsController:AbortController|undefined
const provider=computed(()=>providers.value.find(row=>row.id===form.provider_id))
const providerOptions=computed(()=>providers.value.map(row=>({value:row.id,label:`${row.name} · ${row.model} · 修订 ${row.revision}`,disabled:!row.enabled||!row.has_key})))
const eligibleSamples=computed(()=>samples.value.filter(row=>Date.parse(row.expires_at)>Date.now()&&(form.source==='http_raw'?!!row.origin?.synthetic:!row.origin?.synthetic)))
const sampleOptions=computed(()=>eligibleSamples.value.map(row=>({value:row.id,label:`${row.name} · ${formatBytes(row.size)}`})))
const sample=computed(()=>eligibleSamples.value.find(row=>row.id===form.sample_id))
const frozen=computed(()=>busy.value||unconfirmed.value)
const candidate=computed(()=>selected.value?.candidates.find(row=>row.sid===chosenSID.value)??selected.value?.candidates[0])
const candidateOptions=computed(()=>selected.value?.candidates.map(row=>({value:row.sid,label:`SID ${row.sid} · ${row.title}`}))??[])
const columns=[{title:'检测说明',dataIndex:'title',width:260},{title:'材料来源',key:'source',width:140},{title:'处理状态',key:'state',width:160},{title:'提交时间',key:'time',width:190},{title:'操作',key:'action',width:180}]
async function readOptions(){
  if(stopped||frozen.value)return
  optionsController?.abort();const control=new AbortController();optionsController=control;optionsPending.value=true;optionsError.value=''
  try{
    const [models,evidence]=await Promise.all([session.api.request<{items:ModelProvider[];available:boolean}>('/models/providers',{signal:control.signal}),session.api.request<{items:ReplaySample[];available:boolean}>('/replay/samples',{signal:control.signal})])
    if(control.signal.aborted||stopped)return
    if(!Array.isArray(models.items)||!Array.isArray(evidence.items)||!evidence.items.every(validGenerationSample)||!models.items.every(row=>row&&typeof row.id==='string'&&typeof row.name==='string'&&typeof row.base_url==='string'&&typeof row.model==='string'&&typeof row.enabled==='boolean'&&typeof row.has_key==='boolean'&&typeof row.allow_external==='boolean'&&Number.isSafeInteger(row.revision)&&row.revision>0&&Number.isSafeInteger(row.timeout_seconds)&&row.timeout_seconds>0))throw new Error('模型或样本选项未能完整返回')
    providers.value=models.available?models.items:[];samples.value=evidence.items
  }catch(e){if(!control.signal.aborted)optionsError.value=e instanceof Error?e.message:'生成选项读取失败'}finally{if(optionsController===control&&!stopped)optionsPending.value=false}
}
function openCreate(){if(frozen.value)return;generation.clear();Object.assign(form,{description:'',source:'natural_language',provider_id:undefined,sample_id:undefined,candidate_count:1,allow_context:false});formError.value='';creating.value=true;void readOptions()}
function changeSource(){form.sample_id=undefined;form.allow_context=false;formError.value=''}
function changeProvider(){form.allow_context=false;formError.value=''}
async function submit(){
  if(busy.value||stopped||unconfirmed.value)return
  formError.value=''
  if(!form.description.trim()||[...form.description].length>4000){formError.value='请填写不超过 4,000 字的检测说明';return}
  if(!provider.value?.enabled||!provider.value.has_key){formError.value='请选择已启用并配置凭据的模型';return}
  if(form.source!=='natural_language'&&!sample.value){formError.value='请选择尚在保留期内的对应类型样本';return}
  if(!form.allow_context){formError.value='请确认本次检测说明与样本摘要可发送至所选模型';return}
  const job=await generation.submit({description:form.description,source:form.source,provider_id:provider.value.id,provider_revision:provider.value.revision,sample_id:sample.value?.id??'',sample_sha256:sample.value?.sha256??'',candidate_count:form.candidate_count,allow_context:true})
  if(job){creating.value=false;detailID.value=job.id;viewing.value=true}
}
async function confirm(){const job=await generation.confirm();if(job){creating.value=false;detailID.value=job.id;viewing.value=true}}
async function openDetail(id:string){if(busy.value)return;generation.clear();detailID.value=id;viewing.value=true;adopted.value=null;chosenSID.value=undefined;await generation.load(id)}
function chooseCandidate(value:unknown){if(typeof value==='number')chosenSID.value=value}
async function adopt(){if(!candidate.value)return;const pkg=await generation.adopt(candidate.value);if(pkg){adopted.value=pkg;emit('adopted',pkg);message.success('候选已保存为规则包，请完成装载检查与样本回放')}}
function closeDetail(){if(busy.value)return;viewing.value=false;generation.clear();adopted.value=null}
watch(()=>selected.value?.id,()=>{chosenSID.value=undefined;adopted.value=null})
watch(chosenSID,()=>{adopted.value=null})
onScopeDispose(()=>{stopped=true;optionsController?.abort()})
</script>
<template>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次提交结果尚未确认" description="原请求内容和请求键已保留。确认原请求可读取同一作业，避免重复提交模型调用。" class="section-gap"><template #action><a-button :loading="busy" @click="confirm">确认原请求</a-button></template></a-alert>
  <section class="panel">
    <div class="panel-header"><div><h2>AI 规则生成</h2><p class="page-description">根据自然语言与离线样本生成候选，保留材料引用、模型修订和人工采纳记录。</p></div><a-space><a-button :loading="pending" @click="generation.refresh()">刷新记录</a-button><a-button type="primary" :disabled="!available||frozen" @click="openCreate">生成规则</a-button></a-space></div>
    <div class="panel-body"><a-alert v-if="!pending&&!error&&!available" type="warning" show-icon message="模型执行服务暂不可用" description="当前可查看历史记录；请核对模型凭据、任务队列和服务状态。"/><p v-else class="page-description">候选仅包含 alert 检测规则；模型生成成功不代表原生语法、误报率或攻击结论已通过验证。</p></div>
    <StatePanel :loading="pending&&items.length===0" :error="items.length===0?error:''" :empty="items.length===0" description="暂无规则生成记录。配置模型后，可根据检测说明和离线样本生成候选规则。" @retry="generation.refresh()">
      <div v-if="error" class="panel-body"><a-alert type="warning" show-icon :message="`${error}。当前显示上次读取的记录，请刷新核对。`"/></div>
      <div class="table-wrap"><a-table :columns="columns" :data-source="items" row-key="id" size="small" :pagination="false" :scroll="{x:930}"><template #bodyCell="{column,record}"><template v-if="column.key==='source'">{{ sourceNames[record.source as GenerationSource] }}</template><template v-else-if="column.key==='state'"><span :class="['status',checkClass(record.state)]">{{generationStates[record.state]}}</span><small v-if="record.cancel_requested" class="record-id">取消请求已提交</small></template><template v-else-if="column.key==='time'">{{ formatTime(record.created_at) }}</template><template v-else-if="column.key==='action'"><a-button type="link" :disabled="busy" @click="openDetail(record.id)">查看结果</a-button></template></template></a-table></div>
      <div v-if="next" class="panel-body"><a-button :loading="pending" @click="generation.refresh(next,true)">加载更多</a-button></div>
    </StatePanel>
  </section>
  <a-modal title="AI 规则生成" :open="creating" :width="760" :footer="null" :closable="!busy" :keyboard="!busy" :mask-closable="!busy" :destroy-on-close="true" @cancel="creating=false">
    <a-alert v-if="formError||actionError" type="error" show-icon :message="formError||actionError" class="section-gap"/>
    <a-alert v-if="unconfirmed" type="warning" show-icon message="提交结果尚未确认，输入已锁定" description="请确认原请求；相同请求键不会生成第二个作业。" class="section-gap"/>
    <StatePanel :loading="optionsPending" :error="optionsError" @retry="readOptions">
      <a-form layout="vertical" :model="form" name="rule-generation">
        <a-form-item label="检测说明" name="description" required><a-textarea v-model:value="form.description" :disabled="frozen" :rows="4" :maxlength="4000" show-count placeholder="说明需要检测的协议、请求特征、适用资产范围及应排除的正常行为"/></a-form-item>
        <a-form-item label="材料来源" name="source" required><a-radio-group v-model:value="form.source" :disabled="frozen" @change="changeSource"><a-radio value="natural_language">自然语言</a-radio><a-radio value="pcap">PCAP 样本</a-radio><a-radio value="http_raw">HTTP Raw</a-radio></a-radio-group></a-form-item>
        <a-form-item v-if="form.source!=='natural_language'" label="离线样本" name="sample_id" required><a-select v-model:value="form.sample_id" :options="sampleOptions" :disabled="frozen" @change="form.allow_context=false;formError=''" placeholder="选择对应来源的样本"/><p class="page-description">仅提取前 128 帧中最多 8 段 TCP / UDP 载荷，每段最多 256 字节；不进行流重组或 TLS 解密。</p><a-button v-if="!frozen" type="link" size="small" @click="creating=false;emit('samples')">管理与导入重放样本</a-button><p v-if="sample" class="technical page-description">{{sample.sha256}}</p></a-form-item>
        <a-alert v-if="form.source==='http_raw'" type="info" show-icon message="HTTP Raw 为合成样本" description="原始请求字节封装为离线 TCP 流。握手、地址及时间不代表真实捕获证据，也没有服务器响应。" class="section-gap"/>
        <a-form-item label="生成模型" name="provider_id" required><a-select v-model:value="form.provider_id" :options="providerOptions" :disabled="frozen" placeholder="选择支持严格 JSON 输出的模型" @change="changeProvider"/><p v-if="provider" class="page-description">发送目标：<span class="technical">{{provider.base_url}}</span> · {{provider.allow_external?'允许外部调用':'内部模型'}} · 单次最长 {{provider.timeout_seconds}} 秒</p><p v-if="!providers.some(row=>row.enabled&&row.has_key)" class="page-description">暂无可用模型，请前往 <router-link to="/models">模型配置</router-link> 配置提供方。</p></a-form-item>
        <a-form-item label="候选数量" name="candidate_count" required><a-select v-model:value="form.candidate_count" :disabled="frozen" :options="[1,2,3].map(value=>({value,label:`${value} 条`}))"/></a-form-item>
        <a-form-item><a-checkbox v-model:checked="form.allow_context" :disabled="frozen">允许将本次检测说明与所选样本的有界摘要发送至所选模型</a-checkbox><p class="page-description">共享模型的每日调用额度。未知结果不会自动重试，实际用量以提供方返回为准。</p></a-form-item>
      </a-form>
      <div class="filter-actions"><a-button :disabled="busy" @click="creating=false">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" @click="confirm">确认原请求</a-button><a-button v-else type="primary" :loading="busy" :disabled="!available||optionsPending" @click="submit">提交生成</a-button></div>
    </StatePanel>
  </a-modal>
  <a-modal title="规则生成结果" :open="viewing" :width="940" :footer="null" :closable="!busy" :keyboard="!busy" :mask-closable="!busy" @cancel="closeDetail">
    <StatePanel :loading="loading&&!selected" :error="selected?'':detailError" @retry="generation.load(detailID)">
      <template v-if="selected">
        <a-alert v-if="detailError||actionError" type="error" show-icon :message="detailError||actionError" class="section-gap"/>
        <div class="filter-actions section-gap"><span :class="['status',checkClass(selected.state)]">{{generationStates[selected.state]}}</span><a-button :loading="loading" :disabled="busy" @click="generation.load(selected.id)">刷新结果</a-button><a-button v-if="generationWorking(selected.state)" danger :disabled="busy||selected.cancel_requested" @click="generation.cancel(selected.id)">{{selected.cancel_requested?'取消请求已提交':'取消生成'}}</a-button></div>
        <p class="page-description section-gap">{{generationCodes[selected.result.code]??resultNames[selected.result.code]??'尚未获取处理说明'}}</p>
        <a-alert v-if="selected.state==='uncertain'||selected.cancel_requested&&generationWorking(selected.state)" type="warning" show-icon message="提供方可能已执行请求" description="取消不保证停止模型调用或计费；未确认的结果不会自动重试。" class="section-gap"/>
        <a-descriptions bordered :column="1" size="small" class="section-gap"><a-descriptions-item label="检测说明">{{selected.request.description}}</a-descriptions-item><a-descriptions-item label="模型 / 模板"><span class="technical">{{selected.request.provider_id}}</span> · 修订 {{selected.request.provider_revision}} · {{selected.template}}</a-descriptions-item><a-descriptions-item label="材料来源">{{sourceNames[selected.request.source]}}<template v-if="selected.evidence.sample"> · {{selected.evidence.sample.name}} · {{formatBytes(selected.evidence.sample.size)}}</template></a-descriptions-item><a-descriptions-item label="材料摘要"><span class="technical">{{selected.evidence.sha256}}</span></a-descriptions-item><a-descriptions-item label="创建 / 保留至">{{formatTime(selected.created_at)}} / {{formatTime(selected.expires_at)}}</a-descriptions-item><a-descriptions-item label="耗时 / 令牌用量">{{selected.result.duration_ms??'未确认'}} ms · {{selected.result.usage?`${selected.result.usage.total_tokens} tokens`:'未返回用量'}}</a-descriptions-item></a-descriptions>
        <a-alert v-if="selected.evidence.sample?.origin?.synthetic" type="info" show-icon message="材料包含 HTTP Raw 合成 TCP 流" description="候选规则引用合成样本帧序号；不能据此推断真实捕获、完整响应或攻击结果。" class="section-gap"/>
        <template v-if="candidate">
          <h2 class="section-gap">候选规则</h2><a-select v-if="candidateOptions.length>1" :value="chosenSID??candidate.sid" :options="candidateOptions" @update:value="chooseCandidate" :disabled="busy" style="width:100%" class="section-gap"/>
          <p class="section-gap">{{candidate.title}} · SID {{candidate.sid}} · Suricata {{candidate.engine_version}}</p><RuleEditor :model-value="candidate.rule" readonly/>
          <p class="section-gap">{{candidate.explanation}}</p><ul v-if="candidate.risks.length" class="section-gap"><li v-for="risk in candidate.risks" :key="risk">{{risk}}</li></ul><p v-else class="page-description section-gap">模型未提供风险说明；仍需检查误报、规避行为和适用范围。</p>
          <p class="page-description section-gap">引用帧：{{candidate.references.length?candidate.references.join('、'):'无样本帧引用'}} · <span class="technical">{{candidate.sha256}}</span></p>
          <a-alert v-if="adopted" type="success" show-icon message="候选已保存为规则包" class="section-gap"><template #description>{{adopted.name}} · 修订 {{adopted.revision}}。请在 <router-link to="/rules">规则包</router-link> 完成装载检查、正反样本回放及发布条件核对。</template></a-alert>
          <a-button type="primary" :loading="busy" :disabled="!!adopted||loading||!!detailError" @click="adopt">采纳为规则包</a-button><p class="page-description section-gap">保存原始候选内容与生成来源，不直接同步或发布至探针。保存后可创建人工修订。</p>
        </template>
        <details v-if="selected.evidence.packets.length" class="section-gap"><summary>查看模型材料摘要（{{selected.evidence.packets.length}} 段载荷）</summary><p class="page-description">{{selected.evidence.limited?'材料达到截取或解析限制。':'材料在摘要提取范围内。'}}此摘要不等同于完整通信，原始 PCAP 保持不变。</p><div v-for="packet in selected.evidence.packets" :key="packet.packet" class="section-gap"><p>帧 {{packet.packet}} · {{packet.protocol.toUpperCase()}} · <span class="technical">{{packet.source_ip}}:{{packet.source_port}} → {{packet.destination_ip}}:{{packet.destination_port}}</span> · {{packet.payload_limited?'仅前 256 字节':'已提取当前载荷'}}</p><pre class="technical generation-payload">{{packet.payload_hex}}</pre></div></details>
      </template>
    </StatePanel>
  </a-modal>
</template>

<style scoped>
.generation-payload {white-space:pre-wrap;overflow-wrap:anywhere;max-height:160px;overflow:auto}
</style>
