<script setup lang="ts">
import { computed, shallowRef } from 'vue'
import { Table as ATable, Modal as AModal, Descriptions as ADescriptions, Popconfirm as APopconfirm } from 'ant-design-vue'
import type { SensorTask } from '../types'
import { formatTime, taskNames, taskStates, taskCodes } from '../types'
import ReplayResult from './ReplayResult.vue'
const ADescriptionsItem = ADescriptions.Item
const props = defineProps<{items:readonly SensorTask[];cancellable?:boolean;saving?:boolean;local?:boolean}>()
const emit = defineEmits<{cancel:[task:SensorTask]}>()
const selectedID = shallowRef('')
const selected=computed(()=>props.items.find(row=>row.id===selectedID.value)??null)
const rows = computed(()=>[...props.items])
const columns = computed(()=>[{title:'任务',key:'kind',width:200},{title:'探针',dataIndex:'sensor_id',width:190},{title:'状态',key:'state',width:110},{title:'提交时间',key:'time',width:190},props.local?{title:'平台确认',key:'ack',width:100}:{title:'投递次数',dataIndex:'delivery_count',width:100},{title:'操作',key:'action',width:150}])
function find(id:string){return props.items.find(row=>row.id===id)}
function view(id:string){selectedID.value=id}
function cancel(id:string){const row=find(id);if(row)emit('cancel',row)}
const statusClass=(state:string)=>state==='succeeded'?'status-online':state==='failed'?'status-high':state==='unknown'?'status-medium':'status-unknown'
</script>
<template>
  <div class="table-wrap"><a-table :columns="columns" :data-source="rows" row-key="id" size="small" :pagination="{pageSize:10,showSizeChanger:false,hideOnSinglePage:true}" :scroll="{x:940}">
    <template #bodyCell="{column,record}">
      <template v-if="column.key==='kind'"><button class="link-button" @click="view(record.id)">{{ taskNames[record.kind]??record.kind }}</button><small class="record-id technical">{{ record.id }}</small></template>
      <span v-else-if="column.key==='state'" class="status" :class="statusClass(record.state)">{{ taskStates[record.state]??record.state }}</span>
      <template v-else-if="column.key==='time'">{{ formatTime(record.created_at) }}</template>
      <template v-else-if="column.key==='ack'">{{ record.origin==='local'?'本地任务':record.acknowledged?'已确认':'等待确认' }}</template>
      <template v-else-if="column.key==='action'"><a-space><a-button type="link" @click="view(record.id)">查看</a-button><a-popconfirm v-if="cancellable&&record.state==='queued'&&record.delivery_count===0" title="取消尚未投递的任务？已投递任务需等待设备回执。" @confirm="cancel(record.id)"><a-button type="link" :disabled="saving">取消</a-button></a-popconfirm></a-space></template>
    </template>
  </a-table></div>
  <a-modal title="任务详情" :open="selected!==null" :footer="null" :width="780" @cancel="selectedID=''">
    <div v-if="selected" class="detail-content">
      <a-alert v-if="selected.state==='unknown'" type="warning" show-icon message="执行结果待核实，请核对设备当前状态后处理，避免重复执行。" class="section-gap" />
      <a-alert v-if="selected.receipt.result?.syntax==='passed'&&selected.receipt.result?.replay==='not_run'" type="info" show-icon message="规则装载检查通过；样本回放尚未完成，该结果不授予发布资格。" class="section-gap" />
      <ReplayResult v-if="selected.kind==='rules.replay'&&selected.receipt.result?.replay" :result="selected.receipt.result" :local="selected.origin==='local'" />
      <details :open="selected.kind!=='rules.replay'" class="section-gap"><summary>任务追溯</summary>
      <a-descriptions bordered :column="1" size="small">
        <a-descriptions-item label="任务标识"><span class="technical">{{ selected.id }}</span></a-descriptions-item>
        <a-descriptions-item label="任务 / 状态">{{ taskNames[selected.kind]??selected.kind }} / {{ taskStates[selected.state]??selected.state }}</a-descriptions-item>
        <a-descriptions-item label="探针标识"><span class="technical">{{ selected.sensor_id }}</span></a-descriptions-item>
        <a-descriptions-item label="提交 / 到期时间">{{ formatTime(selected.created_at) }} / {{ formatTime(selected.expires_at) }}</a-descriptions-item>
        <a-descriptions-item label="开始 / 结束时间">{{ formatTime(selected.receipt.started_at) }} / {{ formatTime(selected.receipt.finished_at) }}</a-descriptions-item>
        <a-descriptions-item label="结果说明">{{ selected.receipt.code?(taskCodes[selected.receipt.code]??selected.receipt.code):selected.state==='failed'?'执行失败，请核对执行回执':selected.receipt.state?'无执行异常':'等待设备回执' }}</a-descriptions-item>
      </a-descriptions>
      </details>

      <details><summary>执行回执</summary><pre class="raw-data technical">{{ JSON.stringify(selected.receipt.result??{},null,2) }}</pre></details>
    </div>
  </a-modal>
</template>
