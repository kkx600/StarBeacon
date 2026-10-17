<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import {computed,reactive,ref,shallowRef,watch} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import type {Sensor} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import SensorTable from './SensorTable.vue'
import SensorDetail from './SensorDetail.vue'
import CaptureDialog from './CaptureDialog.vue'
import ResponseDialog from './ResponseDialog.vue'
import TaskWorkspace from './TaskWorkspace.vue'
import ProbePKIWorkspace from './ProbePKIWorkspace.vue'
import GroupTable from './GroupTable.vue'
import ManagementForm from './ManagementForm.vue'
import {useSensors} from './useSensors'
import {useSensorGroups} from './useSensorGroups'
import {useSensorMutation} from './useSensorMutation'
import type {ManagementInput,ManagementTarget,SensorGroup} from './management'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import {session} from '../../session'
const message=useFeedback()
const admin=computed(()=>session.current.value?.role==='admin')
const {view,change:changeView}=useWorkspaceView(admin.value?['devices','groups','tasks','identity']:['devices','groups'])
const views=computed(()=>[{key:'devices',label:'探针列表'},{key:'groups',label:'探针分组'},...(admin.value?[{key:'identity',label:'注册与证书'},{key:'tasks',label:'任务记录'}]:[])])
const sensors=useSensors(),groups=useSensorGroups(),mutation=useSensorMutation()
const tasksWorkspace=ref<InstanceType<typeof TaskWorkspace>|null>(null)
const {items,pending,error,saving,cursors,nextCursor}=sensors
const {page:groupPage,pending:groupPending,error:groupError,cursors:groupCursors,choices,choicesPending,choicesError}=groups
const {busy,unconfirmed,error:actionError}=mutation
const selected=shallowRef<Sensor|null>(null),captureSensor=shallowRef<Sensor|null>(null),editing=shallowRef<ManagementTarget|null>(null),formOpen=shallowRef(false),draft=shallowRef<ManagementInput|undefined>()
const responseSensor=shallowRef<Sensor|null>(null)
const certificateSensor=shallowRef('')
function showCertificates(sensor:Sensor){selected.value=null;certificateSensor.value=sensor.id;changeView('identity')}
const filters=reactive({keyword:'',groupID:'',status:''}),groupFilters=reactive({keyword:'',active:''}),selectedGroupName=shallowRef('')
const locked=computed(()=>busy.value||unconfirmed.value)
const filterGroups=computed(()=>[{value:'',label:'全部分组'},{value:'ungrouped',label:'未分组'},...choices.value.map(g=>({value:g.id,label:g.name})),...(filters.groupID&&filters.groupID!=='ungrouped'&&!choices.value.some(g=>g.id===filters.groupID)?[{value:filters.groupID,label:selectedGroupName.value||'所选分组'}]:[])])
function configure(sensor:Sensor){selected.value=null;captureSensor.value=sensor}
async function change(sensor:Sensor){try{if(await sensors.toggle(sensor))message.success('探针状态保存成功')}catch(e){message.error(e instanceof Error?e.message:'保存失败')}}
function edit(target:ManagementTarget){if(locked.value)return;selected.value=null;mutation.clearError();editing.value=target;draft.value=undefined;formOpen.value=true}
function restoreAttempt(){const frozen=mutation.pendingInput();if(!frozen||!editing.value)return;draft.value=frozen.input;formOpen.value=true}
function members(group:SensorGroup){selectedGroupName.value=group.name;filters.groupID=group.id;filters.keyword='';filters.status='';sensors.search('',group.id,'');changeView('devices')}
async function saved(value:unknown){if(!value)return;formOpen.value=false;editing.value=null;draft.value=undefined;message.success('探针管理操作已确认');await Promise.all([sensors.refresh(),groups.refresh(),groups.loadChoices()])}
async function save(kind:'group'|'metadata',id:string,input:ManagementInput){await saved(await mutation.save(kind,id,input))}
async function confirm(){await saved(await mutation.confirm())}
function refresh(){if(view.value==='tasks'){tasksWorkspace.value?.refresh();return}if(view.value==='groups'){void groups.refresh();void groups.loadChoices()}else void sensors.refresh()}
function reset(){filters.keyword='';filters.groupID='';filters.status='';selectedGroupName.value='';sensors.search('','','')}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id].join('/'),()=>{editing.value=null;selected.value=null;captureSensor.value=null;responseSensor.value=null;formOpen.value=false;draft.value=undefined;reset();groupFilters.keyword='';groupFilters.active=''})
watch(admin,value=>{if(!value&&['identity','tasks'].includes(view.value))changeView('devices')})
</script>
<template>
 <header class="page-header"><div><h1>探针管理</h1><p class="page-description">查看连接、资源和版本，维护当前租户的探针分组与部署信息。</p></div><div class="filter-actions"><a-button v-if="view!=='identity'" :loading="view==='groups'?groupPending:pending" @click="refresh">刷新</a-button><a-button v-if="unconfirmed" type="primary" @click="restoreAttempt">核对原提交</a-button><a-button v-else-if="view==='groups'&&admin" type="primary" :disabled="busy" @click="edit({kind:'group',record:null})">创建分组</a-button></div></header>
 <WorkspaceTabs :active="view" :items="views" label="探针管理功能" @change="changeView" />
 <a-alert v-if="actionError&&!formOpen" type="error" :message="actionError" show-icon class="section-gap" />
 <template v-if="view==='devices'">
  <a-form :model="filters" layout="inline" class="panel sensor-filters" @finish="sensors.search(filters.keyword,filters.groupID,filters.status)">
   <a-form-item label="关键词"><a-input v-model:value="filters.keyword" aria-label="探针关键词" :maxlength="128" placeholder="名称、标识或站点" class="sensor-keyword" /></a-form-item>
   <a-form-item label="探针分组"><a-select v-model:value="filters.groupID" aria-label="筛选探针分组" :options="filterGroups" :loading="choicesPending" class="sensor-select" show-search option-filter-prop="label" /></a-form-item>
   <a-form-item label="连接状态"><a-select v-model:value="filters.status" aria-label="筛选探针状态" class="sensor-select" :options="[{value:'',label:'全部状态'},{value:'online',label:'在线'},{value:'offline',label:'离线'},{value:'disabled',label:'停用'}]" /></a-form-item>
   <a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button :disabled="pending" @click="reset">重置</a-button>
  </a-form>
  <a-alert v-if="choicesError" type="warning" show-icon :message="choicesError" class="section-gap"><template #action><a-button size="small" :loading="choicesPending" @click="groups.loadChoices">刷新分组</a-button></template></a-alert>
  <section class="panel"><div class="panel-header"><h2>探针列表</h2><span>当前页 {{items.length}} 台</span></div><StatePanel :loading="pending" :error="error" :empty="!items.length" description="当前条件下没有探针。请调整筛选条件，或完成采集器身份登记后连接平台。" @retry="sensors.refresh"><SensorTable :items="items" :admin="admin" :saving="saving||locked" @view="selected=$event" @toggle="change" @edit="edit({kind:'metadata',record:$event})" /></StatePanel><div class="sensor-pagination"><a-button :disabled="pending||cursors.length<=1" @click="sensors.previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!nextCursor" @click="sensors.next">下一页</a-button></div></section>
 </template>
 <template v-else-if="view==='groups'">
  <a-form :model="groupFilters" layout="inline" class="panel sensor-filters" @finish="groups.search(groupFilters.keyword,groupFilters.active)"><a-form-item label="分组名称"><a-input v-model:value="groupFilters.keyword" aria-label="分组关键词" :maxlength="128" class="sensor-keyword" /></a-form-item><a-form-item label="分组状态"><a-select v-model:value="groupFilters.active" aria-label="筛选分组状态" class="sensor-select" :options="[{value:'',label:'全部状态'},{value:'true',label:'启用'},{value:'false',label:'停用'}]" /></a-form-item><a-button type="primary" html-type="submit" :loading="groupPending">查询</a-button><a-button :disabled="groupPending" @click="groupFilters.keyword='';groupFilters.active='';groups.search('','')">重置</a-button></a-form>
  <section class="panel"><div class="panel-header"><h2>探针分组</h2><span>当前页 {{groupPage.items.length}} 个</span></div><StatePanel :loading="groupPending" :error="groupError" :empty="!groupPage.items.length" description="当前条件下没有分组。管理员可创建分组，再将探针归入对应站点。" @retry="groups.refresh"><GroupTable :items="groupPage.items" :admin="admin" :locked="locked" @edit="edit({kind:'group',record:$event})" @members="members" /></StatePanel><div class="sensor-pagination"><a-button :disabled="groupPending||groupCursors.length<=1" @click="groups.previous">上一页</a-button><span>第 {{groupCursors.length}} 页</span><a-button :disabled="groupPending||!groupPage.next_cursor" @click="groups.next">下一页</a-button></div></section>
 </template>
 <ProbePKIWorkspace v-else-if="view==='identity'&&admin" :sensor-id="certificateSensor" />
 <TaskWorkspace v-else ref="tasksWorkspace" />
 <SensorDetail :sensor="selected" @close="selected=null" @submitted="selected=null;changeView('tasks')" @configure="configure" @respond="selected=null;responseSensor=$event" @certificates="showCertificates" />
 <CaptureDialog :sensor="captureSensor" @close="captureSensor=null" @submitted="captureSensor=null;changeView('tasks')" />
 <ResponseDialog :sensor="responseSensor" @close="responseSensor=null" @submitted="responseSensor=null;changeView('tasks')" />
 <ManagementForm v-if="formOpen&&editing" :key="(draft?'frozen_':'')+editing.kind+(editing.record?.id??'create')" :target="editing" :draft="draft" :groups="choices" :groups-pending="choicesPending" :groups-error="choicesError" :busy="busy" :unconfirmed="unconfirmed" :error="actionError" @save="save" @confirm="confirm" @close="formOpen=false" @reload-groups="groups.loadChoices" />
</template>
<style scoped>.sensor-filters{display:flex;flex-wrap:wrap;align-items:center;gap:var(--related-gap);padding:var(--panel-inset);margin-bottom:var(--section-gap)}.sensor-filters .ant-form-item{margin:0;min-width:0}.sensor-keyword{width:220px;max-width:100%}.sensor-select{min-width:150px;max-width:240px}.sensor-pagination{display:flex;justify-content:flex-end;align-items:center;flex-wrap:wrap;gap:var(--related-gap);padding:var(--panel-inset)}@media(max-width:800px){.sensor-filters .ant-form-item{flex:1 1 200px}.sensor-keyword,.sensor-select{width:100%;max-width:100%}}</style>
