<script setup lang="ts">
import { computed, shallowRef } from 'vue'
import { Table as ATable, Modal as AModal, Descriptions as ADescriptions } from 'ant-design-vue'
import type { SensorTask,TaskDetailState } from '../types'
import { formatTime, taskNames, taskStates, taskCodes } from '../types'
import ReplayResult from './ReplayResult.vue'
import CaptureResult from './CaptureResult.vue'
import StatePanel from './StatePanel.vue'
import TaskActions from './TaskActions.vue'
import {responseStates} from '../response'
import {basicApplicationState} from '../application'
const ADescriptionsItem = ADescriptions.Item
const props = defineProps<{items:readonly SensorTask[];cancellable?:boolean;reconcilable?:boolean;saving?:boolean;local?:boolean;responseable?:boolean;detail?:TaskDetailState}>()
const emit = defineEmits<{cancel:[task:SensorTask];reconcile:[task:SensorTask];response:[task:SensorTask,kind:'response.read'|'response.revoke'];view:[task:SensorTask];close:[];refreshDetail:[]}>()
const selectedID = shallowRef('')
const selected=computed(()=>props.detail?props.detail.item:props.items.find(row=>row.id===selectedID.value)??null)
const applicationInstalled=computed(()=>{
 const task=selected.value,state=task?.receipt.result
 return task?.kind==='applications.apply'&&task.state==='succeeded'&&basicApplicationState(state)&&state.deployment_id===task.id?state:null
})
const rows = computed(()=>[...props.items])
const columns = computed(()=>[{title:'任务',key:'kind',width:200},{title:'探针',dataIndex:'sensor_id',width:190},{title:'状态',key:'state',width:110},{title:'提交时间',key:'time',width:190},props.local?{title:'平台确认',key:'ack',width:100}:{title:'投递次数',dataIndex:'delivery_count',width:100},{title:'操作',key:'action',width:180}])
function find(id:string){return props.items.find(row=>row.id===id)}
function view(id:string){if(props.detail){const row=find(id);if(row)emit('view',row)}else selectedID.value=id}
function close(){if(props.detail)emit('close');else selectedID.value=''}
const statusClass=(state:string)=>state==='succeeded'?'status-online':state==='failed'?'status-high':state==='unknown'?'status-medium':'status-unknown'
</script>
<template>
  <div class="table-wrap"><a-table :columns="columns" :data-source="rows" row-key="id" size="small" :pagination="{pageSize:10,showSizeChanger:false,hideOnSinglePage:true}" :scroll="{x:970}">
    <template #bodyCell="{column,record}">
      <template v-if="column.key==='kind'"><button class="link-button" @click="view(record.id)">{{ taskNames[record.kind]??record.kind }}</button><small class="record-id technical">{{ record.id }}</small></template>
      <span v-else-if="column.key==='state'" class="status" :class="record.rule_resolution?'status-online':statusClass(record.state)">{{ record.rule_resolution?'已核实':taskStates[record.state]??record.state }}</span>
      <template v-else-if="column.key==='time'">{{ formatTime(record.created_at) }}</template>
      <template v-else-if="column.key==='ack'">{{ record.origin==='local'?'本地任务':record.acknowledged?'已确认':'等待确认' }}</template>
      <template v-else-if="column.key==='action'"><a-space><a-button type="link" @click="view(record.id)">查看</a-button><TaskActions v-if="find(record.id)" :task="find(record.id)!" :cancellable="cancellable" :reconcilable="reconcilable" :responseable="responseable" :saving="saving" :local="local" @cancel="emit('cancel',$event)" @reconcile="emit('reconcile',$event)" @response="(task,kind)=>emit('response',task,kind)" /></a-space></template>
    </template>
  </a-table></div>
  <a-modal title="任务详情" :open="detail?detail.open:selected!==null" :footer="null" :width="780" @cancel="close">
    <StatePanel v-if="detail&&(detail.pending||detail.error)" :loading="detail.pending" :error="detail.error" @retry="emit('refreshDetail')" />
    <div v-if="selected&&!detail?.pending&&!detail?.error" class="detail-content">
      <a-alert v-if="local&&selected.retention_protected" type="info" show-icon message="任务记录受执行确认保护" description="未获平台确认、仍在执行或结果待核实的记录暂不清理。保留截止是原计划期限，不代表任务结果已经核实。" class="section-gap" />
      <a-alert v-if="selected.rule_resolution" type="success" show-icon message="规则核实任务已完成，原中断回执保留供审计追溯。" class="section-gap"><template #description>核实任务 <span class="technical">{{selected.rule_resolution.task_id}}</span> · {{formatTime(selected.rule_resolution.confirmed_at)}}<br>核实时规则摘要 <span class="technical" style="overflow-wrap:anywhere">{{selected.rule_resolution.result.active_sha256}}</span></template></a-alert>
      <a-alert v-else-if="selected.state==='unknown'" type="warning" show-icon message="执行结果待核实，请核对设备当前状态后处理，避免重复执行。" class="section-gap" />
      <a-alert v-if="selected.kind==='rules.validate'&&selected.state==='succeeded'&&selected.receipt.result?.syntax==='passed'&&selected.receipt.result?.replay==='not_run'" type="info" show-icon message="规则装载检查通过；该回执仅证明规则可加载，不授予发布资格。发布前仍需独立正、反样本验证。" class="section-gap" />
      <ReplayResult v-if="selected.kind==='rules.replay'&&selected.receipt.result?.replay" :result="selected.receipt.result" :local="selected.origin==='local'" />
      <CaptureResult v-if="selected.kind==='capture.configure'&&selected.receipt.result?.managed" :result="selected.receipt.result" />
      <section v-if="applicationInstalled" class="application-installation section-gap" aria-label="应用规则安装结果"><h3>应用规则安装</h3><p>采集器已持久安装此规则快照，后续规则变更以独立部署任务为准。</p><dl><dt>安装规则</dt><dd>{{applicationInstalled.rule_count}} 条</dd><dt>安装时间</dt><dd>{{formatTime(applicationInstalled.installed_at??undefined)}}</dd><dt>快照 SHA-256</dt><dd class="technical">{{applicationInstalled.rules_sha256}}</dd><dt>状态 SHA-256</dt><dd class="technical">{{applicationInstalled.state_sha256}}</dd></dl></section>
      <template v-if="selected.response_action"><a-alert type="info" show-icon message="以下为此任务结束时的设备配置回读快照。到期及后续变更需再次回读；实际流量阻断效果尚未观测。" class="section-gap"/><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="设备 / 连接器">{{selected.response_action.device_id}} / {{selected.response_action.connector_id}}</a-descriptions-item><a-descriptions-item label="原租约">{{selected.response_action.lease_id}}</a-descriptions-item><a-descriptions-item label="目标 IP">{{selected.response_action.target_ip}}</a-descriptions-item><a-descriptions-item label="封禁到期时间">{{formatTime(selected.response_action.expires_at)}}</a-descriptions-item><a-descriptions-item label="操作依据">{{selected.response_action.reason}}</a-descriptions-item><a-descriptions-item label="配置回读快照">{{responseStates[String((selected.receipt.result?.observation as Record<string,unknown>|undefined)?.state??'unknown')]??'状态待核查'}}</a-descriptions-item><a-descriptions-item label="回读时间">{{formatTime((selected.receipt.result?.observation as Record<string,unknown>|undefined)?.observed_at as string|undefined)}}</a-descriptions-item></a-descriptions></template>
      <details :open="selected.kind!=='rules.replay'" class="section-gap"><summary>任务追溯</summary>
      <a-descriptions bordered :column="1" size="small">
        <a-descriptions-item label="任务标识"><span class="technical">{{ selected.id }}</span></a-descriptions-item>
        <a-descriptions-item label="任务 / 状态">{{ taskNames[selected.kind]??selected.kind }} / {{ taskStates[selected.state]??selected.state }}</a-descriptions-item>
        <a-descriptions-item label="探针标识"><span class="technical">{{ selected.sensor_id }}</span></a-descriptions-item>
        <a-descriptions-item label="提交 / 执行截止">{{ formatTime(selected.created_at) }} / {{ formatTime(selected.expires_at) }}</a-descriptions-item>
        <a-descriptions-item v-if="selected.retain_until" label="记录保留截止">{{formatTime(selected.retain_until)}}</a-descriptions-item>
        <a-descriptions-item label="开始 / 结束时间">{{ formatTime(selected.receipt.started_at) }} / {{ formatTime(selected.receipt.finished_at) }}</a-descriptions-item>
        <a-descriptions-item label="结果说明">{{ selected.receipt.code?(taskCodes[selected.receipt.code]??selected.receipt.code):selected.state==='failed'?'执行失败，请核对执行回执':selected.receipt.state?'无执行异常':'等待设备回执' }}</a-descriptions-item>
      </a-descriptions>
      </details>

      <details><summary>执行回执</summary><pre class="raw-data technical">{{ JSON.stringify(selected.receipt.result??{},null,2) }}</pre></details>
    </div>
    <div v-if="detail" class="filter-actions section-gap"><TaskActions v-if="selected&&!detail.pending&&!detail.error" :task="selected" :cancellable="cancellable" :reconcilable="reconcilable" :responseable="responseable" :saving="saving" :local="local" @cancel="emit('cancel',$event)" @reconcile="emit('reconcile',$event)" @response="(task,kind)=>emit('response',task,kind)" /><a-button :loading="detail.pending" @click="emit('refreshDetail')">刷新详情</a-button><a-button @click="close">关闭</a-button></div>
  </a-modal>
</template>
<style scoped>
.application-installation h3{margin:0 0 8px;font-size:16px}.application-installation dl{display:grid;grid-template-columns:120px minmax(0,1fr);gap:8px;margin:12px 0}.application-installation dt{color:var(--muted)}.application-installation dd{margin:0;overflow-wrap:anywhere}
</style>
