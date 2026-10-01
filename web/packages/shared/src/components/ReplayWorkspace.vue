<script setup lang="ts">
import { computed,onMounted,onScopeDispose,reactive,shallowRef } from 'vue'
import { Table as ATable,Modal as AModal,Select as ASelect,Radio as ARadio,message } from 'ant-design-vue'
import type { ApiClient } from '../api'
import type { ReplaySample,RulePackage,Sensor,SensorTask } from '../types'
import { formatTime } from '../types'
import StatePanel from './StatePanel.vue'
import TaskTable from './TaskTable.vue'
const ARadioGroup=ARadio.Group
const props=defineProps<{api:ApiClient;local?:boolean}>()
const items=shallowRef<ReplaySample[]>([]),tasks=shallowRef<SensorTask[]>([]),sensors=shallowRef<Sensor[]>([]),packages=shallowRef<RulePackage[]>([])
const pending=shallowRef(true),error=shallowRef(''),taskError=shallowRef(''),available=shallowRef(false),registered=shallowRef(true)
const importing=shallowRef(false),uploading=shallowRef(false),file=shallowRef<File>(),uploadError=shallowRef('')
const selected=shallowRef<ReplaySample|null>(null),saving=shallowRef(false),formError=shallowRef(''),accepted=shallowRef('')
const form=reactive({sensor_id:undefined as string|undefined,rule_mode:'package',package_id:undefined as string|undefined,rules:''})
let controller:AbortController|undefined,taskKey:string|undefined,timer:ReturnType<typeof setTimeout>|undefined,stopped=false,refreshFailures=0
const sensorOptions=computed(()=>sensors.value.map(row=>({value:row.id,label:`${row.name} · ${row.status==='online'?'在线':'离线'}`,disabled:!row.active||!row.health.task_capabilities?.includes('rules.replay')})))
const packageOptions=computed(()=>packages.value.map(row=>({value:row.id,label:`${row.name} · 修订 ${row.revision}`})))
const registeredAllowed=computed(()=>props.local?registered.value:(sensors.value.find(row=>row.id===form.sensor_id)?.health.registered_rules_available??false))
const replayTasks=computed(()=>props.local?tasks.value:tasks.value.filter(row=>row.kind==='rules.replay'))
const columns=[{title:'样本名称',key:'name',width:240},{title:'格式 / 大小',key:'size',width:150},{title:'SHA-256',key:'sha',width:200},{title:'导入时间',key:'created',width:190},{title:'保留至',key:'expires',width:190},{title:'操作',key:'action',width:120}]
const size=(bytes:number)=>bytes<1024?`${bytes} B`:bytes<1024*1024?`${(bytes/1024).toFixed(1)} KiB`:`${(bytes/1024/1024).toFixed(1)} MiB`
function schedule(failed=false){
  if(timer)clearTimeout(timer)
  if(stopped)return
  if(failed&&refreshFailures>=3)return
  if(failed||tasks.value.some(row=>['queued','delivered','running'].includes(row.state)))timer=setTimeout(()=>refresh(false),failed?5000*2**Math.max(0,refreshFailures-1):5000)
}
async function refresh(showLoading=true){
  controller?.abort()
  const current=new AbortController();controller=current
  if(showLoading){pending.value=true;refreshFailures=0}
  const [samples,result]=await Promise.allSettled([
    props.api.request<{items:ReplaySample[];available:boolean;registered_rules_available?:boolean}>('/replay/samples',{signal:current.signal}),
    props.api.request<{items:SensorTask[]}>('/tasks',{signal:current.signal}),
  ])
  if(current.signal.aborted)return
  if(samples.status==='fulfilled'){items.value=samples.value.items;available.value=samples.value.available;registered.value=samples.value.registered_rules_available??true;error.value=''}
  else error.value=samples.reason instanceof Error?samples.reason.message:'重放样本读取失败'
  if(result.status==='fulfilled'){tasks.value=result.value.items;taskError.value=''}
  else taskError.value=result.reason instanceof Error?result.reason.message:'任务状态读取失败'
  const failed=samples.status==='rejected'||result.status==='rejected'
  if(failed)refreshFailures++;else refreshFailures=0
  pending.value=false;schedule(failed)
}
function chooseFile(event:Event){file.value=(event.target as HTMLInputElement).files?.[0];uploadError.value=''}
async function upload(){const current=file.value;if(!current){uploadError.value='请选择 PCAP 或 PCAPNG 文件';return}if(current.size<24||current.size>100*1024*1024){uploadError.value='文件大小必须为 24 字节至 100 MiB';return}uploading.value=true;uploadError.value='';try{await props.api.request<ReplaySample>('/replay/samples',{method:'POST',file:current});importing.value=false;file.value=undefined;message.success('样本导入成功，可选择规则执行重放');await refresh()}catch(e){uploadError.value=e instanceof Error?e.message:'样本导入失败'}finally{uploading.value=false}}
async function open(id:string){const sample=items.value.find(row=>row.id===id);if(!sample)return;selected.value=sample;Object.assign(form,{sensor_id:undefined,rule_mode:'package',package_id:undefined,rules:''});taskKey=undefined;formError.value='';accepted.value='';if(props.local)return;saving.value=true;try{const [ss,ps]=await Promise.all([props.api.request<{items:Sensor[]}>('/sensors'),props.api.request<{items:RulePackage[]}>('/rule-packages')]);sensors.value=ss.items;packages.value=ps.items}catch(e){formError.value=e instanceof Error?e.message:'执行选项读取失败'}finally{saving.value=false}}
function changed(){if(form.rule_mode==='registered'&&!registeredAllowed.value)form.rule_mode='package';taskKey=undefined;accepted.value='';formError.value=''}
async function submit(){if(!selected.value)return;if(!props.local&&!form.sensor_id){formError.value='请选择具有离线重放能力的探针';return}if(form.rule_mode==='package'&&(props.local?!form.rules.trim():!form.package_id)){formError.value=props.local?'请输入用于本次重放的规则':'请选择规则包修订';return};if(props.local&&new TextEncoder().encode(form.rules).length>900*1024){formError.value='规则文本超过 900 KiB';return}saving.value=true;formError.value='';taskKey??=crypto.randomUUID();try{let path='/replay/tasks';let body:Record<string,unknown>={sample_id:selected.value.id,rule_mode:form.rule_mode,rules:form.rule_mode==='package'?form.rules:''};if(!props.local){path=`/sensors/${encodeURIComponent(form.sensor_id!)}/tasks`;const pkg=packages.value.find(row=>row.id===form.package_id);body={kind:'rules.replay',sample_id:selected.value.id,rule_mode:form.rule_mode,...(form.rule_mode==='package'?{package_id:pkg?.id,revision:pkg?.revision}:{})}};const result=await props.api.request<{id:string}>(path,{method:'POST',body,headers:{'Idempotency-Key':taskKey}});accepted.value=result.id;await refresh(false)}catch(e){formError.value=e instanceof Error?e.message:'重放任务提交失败'}finally{saving.value=false}}
onMounted(()=>refresh());onScopeDispose(()=>{stopped=true;controller?.abort();if(timer)clearTimeout(timer)})
</script>
<template>
  <section class="panel">
    <div class="panel-header"><div><h2>PCAP 重放</h2><p class="page-description">导入离线样本，使用登记规则快照或指定规则排查检测问题。</p></div><a-space><a-button :loading="pending" @click="refresh()">刷新</a-button><a-button type="primary" :disabled="!available" @click="importing=true;uploadError='';file=undefined">导入 PCAP</a-button></a-space></div>
    <div class="panel-body"><a-alert v-if="!pending&&!error&&!available" type="warning" show-icon :message="local?'离线重放引擎或隔离环境未配置，请联系管理员。':'平台样本存储未配置，请联系管理员。'" class="section-gap" /><p class="page-description">支持 PCAP / PCAPNG，单文件上限 100 MiB。样本按保留策略存储，默认 180 天；执行前核验 SHA-256。重放不向真实网络发包。</p></div>
    <StatePanel :loading="pending" :error="error" :empty="items.length===0" description="暂无重放样本，请导入用于规则验证或故障定位的 PCAP。" @retry="refresh()"><div class="table-wrap"><a-table :columns="columns" :data-source="items" row-key="id" size="small" :pagination="{pageSize:5,hideOnSinglePage:true,showSizeChanger:false}" :scroll="{x:1090}"><template #bodyCell="{column,record}"><template v-if="column.key==='name'"><button class="link-button" :disabled="!available" @click="open(record.id)">{{ record.name }}</button><small class="record-id technical">{{ record.id }}</small></template><template v-else-if="column.key==='size'">{{ record.format.toUpperCase() }} · {{ size(record.size) }}</template><span v-else-if="column.key==='sha'" class="technical" :title="record.sha256">{{ record.sha256.slice(0,20) }}…</span><template v-else-if="column.key==='created'">{{ formatTime(record.created_at) }}</template><template v-else-if="column.key==='expires'">{{ formatTime(record.expires_at) }}</template><a-button v-else-if="column.key==='action'" type="link" :disabled="!available" @click="open(record.id)">重放测试</a-button></template></a-table></div></StatePanel>
  </section>
  <section class="panel"><div class="panel-header"><h2>{{ local?'任务记录':'重放任务' }}</h2><span>{{ local?'包含本地任务与平台任务':'选定探针的执行回执' }}</span></div><div v-if="taskError&&tasks.length>0" class="panel-body"><a-alert type="warning" show-icon message="任务状态更新失败" :description="`${taskError}。当前显示上次成功读取的状态，请刷新后核实执行结果。`"><template #action><a-button size="small" :loading="pending" @click="refresh()">重试</a-button></template></a-alert></div><StatePanel :loading="pending&&tasks.length===0" :error="tasks.length===0?taskError:''" :empty="replayTasks.length===0" @retry="refresh()" description="暂无执行任务。提交重放测试后，可在这里查看包处理统计、命中规则和失败原因。"><TaskTable :items="replayTasks" :local="local" /></StatePanel></section>
  <a-modal title="导入 PCAP" :open="importing" :confirm-loading="uploading" ok-text="导入样本" :closable="!uploading" :mask-closable="!uploading" :keyboard="!uploading" :cancel-button-props="{disabled:uploading}" @ok="upload" @cancel="importing=false"><a-alert v-if="uploadError" type="error" show-icon :message="uploadError" class="section-gap" /><a-form layout="vertical"><a-form-item label="PCAP 文件" html-for="replay-file" required><input id="replay-file" type="file" accept=".pcap,.pcapng" :disabled="uploading" @change="chooseFile" /><p class="page-description">选择原始 PCAP 或 PCAPNG 文件，最大 100 MiB，不支持压缩包。</p></a-form-item></a-form><p v-if="file">{{ file.name }} · {{ size(file.size) }}</p></a-modal>
  <a-modal title="PCAP 重放测试" :open="selected!==null" :width="780" :footer="null" :closable="!saving" :mask-closable="!saving" :keyboard="!saving" @cancel="selected=null"><template v-if="selected"><p class="section-gap">{{ selected.name }} · {{ size(selected.size) }}</p><a-alert v-if="formError" type="error" show-icon :message="formError" class="section-gap" /><a-alert v-if="accepted" type="success" show-icon message="重放任务已受理" class="section-gap"><template #description><span class="technical">{{ accepted }}</span>，执行结果会更新到任务记录中。</template></a-alert>
    <a-form layout="vertical" :model="form" name="replay-test"><a-form-item v-if="!local" label="执行探针" name="sensor_id" required><a-select v-model:value="form.sensor_id" :options="sensorOptions" :disabled="saving" placeholder="选择具有离线重放能力的探针" @change="changed" /></a-form-item><a-form-item label="规则来源" name="rule_mode" required><a-radio-group v-model:value="form.rule_mode" :disabled="saving" @change="changed"><a-radio value="package">{{ local?'指定规则':'指定规则包修订' }}</a-radio><a-radio value="registered" :disabled="!registeredAllowed">登记规则快照</a-radio></a-radio-group><p v-if="!local&&form.sensor_id&&!registeredAllowed" class="page-description">该探针未登记规则快照，可选择指定规则包修订。</p></a-form-item><a-form-item v-if="form.rule_mode==='package'&&!local" label="规则包修订" name="package_id" required><a-select v-model:value="form.package_id" :options="packageOptions" :disabled="saving" placeholder="选择规则包与修订" @change="changed" /></a-form-item><a-form-item v-if="form.rule_mode==='package'&&local" label="规则文本" name="rules" required><a-textarea v-model:value="form.rules" :rows="8" :disabled="saving" class="technical" placeholder="每行一条 Suricata alert 规则，规则仅用于本次离线重放" @change="changed" /></a-form-item></a-form>
    <a-alert type="info" show-icon message="离线检测使用受限配置：单次最多 100 万包、重组深度 1 MiB、校验和检查、执行期限 2 分钟。结果与实时检测配置可能存在差异。" class="section-gap" /><a-button type="primary" :loading="saving" :disabled="!!accepted" @click="submit">执行重放</a-button>
  </template></a-modal>
</template>
