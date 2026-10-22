<script setup lang="ts">
import {ref} from 'vue'
import {Modal as AModal,Tag as ATag,Descriptions as ADescriptions,Tabs as ATabs,Timeline as ATimeline,Collapse as ACollapse} from 'ant-design-vue'
const ADescriptionsItem=ADescriptions.Item,ATabPane=ATabs.TabPane,ATimelineItem=ATimeline.Item,ACollapsePanel=ACollapse.Panel
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {incidentStatuses,incidentCategories,incidentSeverities,type IncidentRecord} from './incident'
defineProps<{record:IncidentRecord|null;pending:boolean;error:string;history:readonly IncidentRecord[];historyPending:boolean;historyError:string;next:string}>()
const emit=defineEmits<{close:[];edit:[];tasks:[];notes:[];reload:[];history:[before?:string]}>()
const active=ref('overview')
function changeTab(value:unknown){if(value==='history')emit('history')}
</script>
<template>
 <a-modal :open="true" title="事件调查" :width="920" :footer="null" @cancel="emit('close')">
  <StatePanel :loading="pending" :error="error" @retry="emit('reload')">
   <template v-if="record">
    <div class="incident-detail-actions"><a-tag :color="record.spec.status==='closed'?'green':record.spec.status==='investigating'?'blue':'orange'">{{incidentStatuses[record.spec.status]}}</a-tag><div class="filter-actions"><a-button @click="emit('notes')">调查笔记</a-button><a-button @click="emit('tasks')">协作任务</a-button><a-button type="primary" @click="emit('edit')">{{record.spec.status==='closed'?'重开或复核':'记录调查'}}</a-button></div></div>
    <a-tabs v-model:active-key="active" @change="changeTab"><a-tab-pane key="overview" tab="调查概览">
     <h2 class="incident-title">{{record.spec.title}}</h2><p class="incident-text">{{record.spec.summary}}</p>
     <a-descriptions bordered :column="1" size="small"><a-descriptions-item label="事件标识"><span class="technical">{{record.id}}</span></a-descriptions-item><a-descriptions-item label="分类 / 严重度">{{incidentCategories[record.spec.category]}} / {{incidentSeverities[record.spec.severity]}}</a-descriptions-item><a-descriptions-item label="责任人">{{record.owner_name||'待分派'}}</a-descriptions-item><a-descriptions-item label="调查修订 / 记录时间">{{record.revision}} / {{formatTime(record.recorded_at)}}</a-descriptions-item><a-descriptions-item label="建立时间">{{formatTime(record.created_at)}}</a-descriptions-item><a-descriptions-item label="当前修订保留期限">{{formatTime(record.expires_at)}} · {{record.spec.status==='closed'?'已结案记录按固化期限保留':'未关闭事件及其历史受保护'}}</a-descriptions-item></a-descriptions>
     <h3>关联告警</h3><a-empty v-if="!record.alerts.length" description="当前事件来自人工线索，未关联检测告警。"/>
     <div v-for="source in record.alerts" :key="source.event_id" class="incident-source"><div><strong class="technical">{{source.event_id}}</strong> · {{source.sensor_id}}</div><div class="muted">发生 {{formatTime(source.event_time)}} · 观测 {{formatTime(source.observed_at)}}</div><div class="technical">{{source.raw_sha256}}</div></div>
     <template v-if="record.spec.closure"><h3>结案材料</h3><a-tag>{{record.spec.closure.reason==='resolved'?'确认处置完成':'确认误报'}}</a-tag><dl class="incident-closure"><template v-for="[label,value] in [['根因说明',record.spec.closure.root_cause],['影响范围',record.spec.closure.impact],['修复措施',record.spec.closure.remediation],['复测说明',record.spec.closure.verification]]" :key="label"><dt>{{label}}</dt><dd>{{value}}</dd></template></dl><p v-for="reference in record.spec.closure.evidence" :key="reference" class="technical">{{reference}}</p></template>
     <a-alert type="info" show-icon message="人工记录和证据引用不代表已核实设备封禁或攻击效果，原始检测事实保留在告警数据集中。" class="section-gap"/>
    </a-tab-pane><a-tab-pane key="history" tab="调查时间线">
     <StatePanel :loading="historyPending" :error="historyError" :empty="!history.length" description="当前条件下没有可读取的调查修订。" @retry="emit('history')"><a-timeline><a-timeline-item v-for="entry in history" :key="entry.revision"><strong>修订 {{entry.revision}} · {{incidentStatuses[entry.spec.status]}}</strong><div class="muted">{{entry.actor_name}} · {{formatTime(entry.recorded_at)}} · 责任人 {{entry.owner_name||'待分派'}}</div><p class="incident-text">{{entry.note}}</p><a-collapse :bordered="false"><a-collapse-panel :key="entry.revision" header="该次调查材料"><p class="incident-text">{{entry.spec.title}} · {{incidentCategories[entry.spec.category]}} · {{incidentSeverities[entry.spec.severity]}}</p><p class="incident-text">{{entry.spec.summary}}</p><div v-for="source in entry.alerts" :key="source.event_id" class="incident-source"><div class="technical">{{source.event_id}} · {{source.sensor_id}}</div><div class="technical">{{source.raw_sha256}}</div></div><template v-if="entry.spec.closure"><a-tag>{{entry.spec.closure.reason==='resolved'?'确认处置完成':'确认误报'}}</a-tag><dl class="incident-closure"><template v-for="[label,value] in [['根因说明',entry.spec.closure.root_cause],['影响范围',entry.spec.closure.impact],['修复措施',entry.spec.closure.remediation],['复测说明',entry.spec.closure.verification]]" :key="label"><dt>{{label}}</dt><dd>{{value}}</dd></template></dl><p v-for="reference in entry.spec.closure.evidence" :key="reference" class="technical">{{reference}}</p></template></a-collapse-panel></a-collapse></a-timeline-item></a-timeline></StatePanel><a-button v-if="next" :loading="historyPending" @click="emit('history',next)">读取更早记录</a-button>
    </a-tab-pane></a-tabs>
   </template>
  </StatePanel>
 </a-modal>
</template>
<style scoped>.incident-detail-actions{display:flex;justify-content:space-between;align-items:center;gap:var(--related-gap)}.incident-title,.incident-text,.incident-source,.incident-closure dd{overflow-wrap:anywhere;white-space:pre-wrap}.incident-title{font-size:18px;margin:8px 0}.incident-source{padding:12px;border:1px solid var(--line);border-radius:8px;margin-bottom:8px}.incident-source .technical{font-size:12px}.incident-closure dt{font-weight:600;margin-top:12px}.incident-closure dd{margin:4px 0 0}</style>
