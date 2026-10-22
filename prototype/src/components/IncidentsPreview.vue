<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import type {PreviewState} from '../models'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
import IncidentNotesPreview from './IncidentNotesPreview.vue'
import IncidentDetail from '../../../web/platform/src/features/incidents/IncidentDetail.vue'
import IncidentForm from '../../../web/platform/src/features/incidents/IncidentForm.vue'
import IncidentTasksModal from '../../../web/platform/src/features/incidents/IncidentTasksModal.vue'
import type {IncidentRecord,IncidentInput} from '../../../web/platform/src/features/incidents/incident'
import type {IncidentTaskRecord,IncidentTaskInput,IncidentTaskAttempt} from '../../../web/platform/src/features/incidents/incidentTask'
import type {IncidentTasksState} from '../../../web/platform/src/features/incidents/useIncidentTasks'

const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>(),route=useRoute(),router=useRouter()
const at='2026-10-18T01:00:00Z',expires='2027-04-16T01:00:00Z'
const owners=[{id:'admin_example',name:'陈宁（示例）'}]
const original:IncidentRecord={id:'incident_example',revision:2,spec:{title:'办公区异常请求调查（示例）',category:'network_intrusion',status:'investigating',severity:'high',summary:'核对网络检测事实、原包与业务影响，记录人工复核材料。',owner_id:owners[0]!.id,closure:null},owner_name:owners[0]!.name,alerts:[],note:'登记授权示例材料。',actor_id:owners[0]!.id,actor_name:owners[0]!.name,created_at:at,recorded_at:at,expires_at:expires}
const parent=shallowRef(original),detailOpen=shallowRef(false),formOpen=shallowRef(false),caseError=shallowRef(''),taskOpen=shallowRef(false),notesOpen=shallowRef(false)
const example:IncidentTaskRecord={id:'case_task_example',incident_id:original.id,incident_revision:original.revision,revision:2,spec:{title:'核对原始请求与响应',description:'对照保留中的原包与应用日志，记录观测到的事实和待确认的缺口。',status:'in_progress',priority:'high',assignee_id:owners[0]!.id,due_at:'2026-10-18T10:30:15.123456789Z',resolution:''},assignee_name:owners[0]!.name,note:'已读取授权示例材料，继续核对业务影响。',actor_id:owners[0]!.id,actor_name:owners[0]!.name,created_at:at,recorded_at:'2026-10-18T01:10:00Z',expires_at:'2027-04-16T01:10:00Z'}
const initialTask:IncidentTaskRecord={...example,revision:1,spec:{...example.spec,status:'open'},note:'建立协作任务',recorded_at:at,expires_at:expires}
const records=shallowRef([example]),allHistory=shallowRef([example,initialTask])
const page=shallowRef({items:[example],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
const selected=shallowRef<IncidentTaskRecord|null>(null),detailPending=shallowRef(false),detailError=shallowRef(''),history=shallowRef<IncidentTaskRecord[]>([]),historyNext=shallowRef(''),historyPending=shallowRef(false),historyError=shallowRef(''),historyLoaded=shallowRef(false)
const busy=shallowRef(false),unconfirmed=shallowRef(false),actionError=shallowRef('')
let filter='',attempt:IncidentTaskAttempt|undefined
function refresh(){page.value={items:records.value.filter(row=>!filter||row.spec.status===filter),next_cursor:''};pending.value=false;error.value='';return Promise.resolve()}
function clearSelection(){selected.value=null;history.value=[];historyLoaded.value=false;detailError.value='';historyError.value=''}
function select(id:string){clearSelection();selected.value=records.value.find(row=>row.id===id)??null;return Promise.resolve()}
function loadHistory(){history.value=allHistory.value.filter(row=>row.id===selected.value?.id);historyLoaded.value=true;return Promise.resolve()}
function save(id:string,input:IncidentTaskInput){const row:IncidentTaskRecord={...example,id:id||'case_task_example_created',incident_revision:input.incident_revision,revision:'expected_revision' in input?input.expected_revision+1:1,spec:structuredClone(input.spec),assignee_name:owners.find(owner=>owner.id===input.spec.assignee_id)?.name??'',note:'note' in input?input.note:'建立协作任务'};records.value=[row,...records.value.filter(item=>item.id!==row.id)];allHistory.value=[row,...allHistory.value];unconfirmed.value=false;actionError.value='';attempt=undefined;void refresh();return Promise.resolve(row)}
const taskState:IncidentTasksState={page,pending,error,cursors,selected,detailPending,detailError,history,historyNext,historyPending,historyError,historyLoaded,busy,unconfirmed,actionError,refresh,search(value:string){filter=value;void refresh()},next(){},previous(){},select,clearSelection,loadHistory,save,pendingInput(){return attempt?structuredClone(attempt):undefined},confirm(){return attempt?save(attempt.id,attempt.input):Promise.resolve(undefined)},clearActionError(){actionError.value=''}}
watch(()=>[props.state,route.query.panel,route.query.task_state,route.query.note_state],()=>{
 const closed=route.query.task_state==='closed'||route.query.note_state==='closed'
 parent.value=closed?{...original,spec:{...original.spec,status:'closed',closure:{reason:'false_positive',root_cause:'授权示例',impact:'合成材料',remediation:'规则复核',verification:'已核对示例依据',evidence:[]}}}:original
 detailOpen.value=props.state==='detail'&&!['tasks','notes'].includes(String(route.query.panel));formOpen.value=props.state==='action'&&!['tasks','notes'].includes(String(route.query.panel));taskOpen.value=route.query.panel==='tasks';notesOpen.value=route.query.panel==='notes';filter='';records.value=route.query.task_state==='empty'?[]:closed?[{...example,spec:{...example.spec,status:'completed',resolution:'已核对授权示例的原包与业务材料。'}}]:[example];void refresh();pending.value=route.query.task_state==='loading';error.value=route.query.task_state==='error'?'协作任务暂时无法读取，请重试。':'';clearSelection();attempt=undefined;unconfirmed.value=false;actionError.value=''
 if(route.query.task_state==='unknown'){attempt={parent:original,id:example.id,input:{incident_revision:original.revision,expected_revision:example.revision,spec:example.spec,note:'提交人工核对进展。'}};unconfirmed.value=true;actionError.value='提交结果尚未确认，请使用原请求核对。'}
},{immediate:true})
const columns=[{title:'事件标题',key:'title',width:300},{title:'状态',key:'status',width:120},{title:'责任人',dataIndex:'owner_name',width:170},{title:'建立时间',key:'time',width:190},{title:'操作',key:'actions',width:100}]
const empty=computed(()=>['empty','loading','error'].includes(props.state))
function saveCase(input:IncidentInput){if(input.spec.status==='closed'&&records.value.some(task=>task.spec.status==='open'||task.spec.status==='in_progress')){caseError.value='当前事件仍有未完成任务，请完成或取消任务后再结案。';return};caseError.value='';parent.value={...parent.value,revision:parent.value.revision+1,spec:input.spec,note:'note' in input?input.note:'建立人工线索'};formOpen.value=false;emit('state','data')}
function tasks(){detailOpen.value=false;formOpen.value=false;notesOpen.value=false;taskOpen.value=true}
function notes(){detailOpen.value=false;formOpen.value=false;taskOpen.value=false;notesOpen.value=true;void router.push({query:{...route.query,panel:'notes',state:'data'},hash:route.hash})}
function closeNotes(){notesOpen.value=false;void router.replace({query:{...route.query,panel:undefined,state:'data'},hash:route.hash})}
</script>
<template>
 <PageHeader title="事件调查" description="关联检测事实与人工线索，记录责任分派、协作任务和可复核的结案依据。"><a-button @click="emit('state','data')">刷新</a-button><a-button type="primary" @click="formOpen=true;detailOpen=false;taskOpen=false;notesOpen=false">建立事件</a-button></PageHeader>
 <a-alert type="info" show-icon message="本页面为合成示例，复用工程调查与协作组件。记录保留180天，可按分类策略配置；原型不提交调查或设备操作。" class="section-gap"/>
 <section class="panel"><StatePanel v-if="empty" :state="state as 'empty'|'loading'|'error'" title="安全事件" description="当前条件下没有可读取的事件调查。" action="重新加载" @action="emit('state','data')"/><a-table v-else :data-source="[parent]" :columns="columns" row-key="id" :pagination="false" :scroll="{x:880}"><template #bodyCell="{column,record}"><a-button v-if="column.key==='title'" type="link" @click="detailOpen=true;formOpen=false;taskOpen=false;notesOpen=false">{{record.spec.title}}</a-button><a-tag v-else-if="column.key==='status'" :color="record.spec.status==='closed'?'green':'blue'">{{record.spec.status==='closed'?'已结案':'调查中'}}</a-tag><span v-else-if="column.key==='time'">2026-10-18 09:00:00</span><a-button v-else-if="column.key==='actions'" type="link" @click="detailOpen=true;formOpen=false;taskOpen=false;notesOpen=false">查看</a-button></template></a-table></section>
 <IncidentDetail v-if="detailOpen" :record="parent" :pending="false" error="" :history="[parent]" :history-pending="false" history-error="" next="" @close="detailOpen=false" @edit="detailOpen=false;formOpen=true" @tasks="tasks" @notes="notes" @reload="()=>{}" @history="()=>{}"/>
 <IncidentForm v-if="formOpen" :record="state==='action'?null:parent" :assignees="owners" :assignee-pending="false" assignee-error="" :busy="false" :unconfirmed="false" :error="caseError" @save="saveCase" @close="formOpen=false"/>
 <IncidentTasksModal v-if="taskOpen" :parent="parent" :state="taskState" :assignees="owners" :owner-pending="false" owner-error="" :parent-pending="false" parent-error="" @close="taskOpen=false;notesOpen=false" @reload-parent="refresh" @reload-owners="()=>{}"/>
 <IncidentNotesPreview :open="notesOpen" :parent="parent" :scenario="typeof route.query.note_state==='string'?route.query.note_state:undefined" @close="closeNotes"/>
</template>
