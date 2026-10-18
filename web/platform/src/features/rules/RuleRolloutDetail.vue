<script setup lang="ts">
import {shallowRef,watch} from 'vue'
import {Table as ATable,Modal as AModal,Tag as ATag,Descriptions as ADescriptions,DescriptionsItem as ADescriptionsItem} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {rolloutStates,rolloutCodes,targetStates,type RuleRollout,type RolloutTarget} from './rollout'
import {syncStates,syncCodes} from './sync'
const props=defineProps<{rollout:RuleRollout;taskPath?:string}>()
const target=shallowRef<RolloutTarget>()
watch(()=>props.rollout,()=>{target.value=undefined})
const columns=[{title:'探针 / 批次',key:'sensor',width:240},{title:'冻结计划',key:'plan',width:220},{title:'执行状态',key:'state',width:260},{title:'操作',key:'action',width:110}]
const stages=['装载检查','正样本重放','反样本重放','规则发布']
function color(s:string){return s==='succeeded'?'success':s==='blocked'?'error':s==='stopping'||s==='stopped'?'warning':'processing'}
function inspect(ordinal:number){target.value=props.rollout.targets?.find(t=>t.ordinal===ordinal)}
</script>
<template>
 <a-alert :type="rollout.state==='blocked'?'error':rollout.state==='succeeded'?'success':'info'" show-icon :message="rolloutStates[rollout.state]" :description="(rolloutCodes[rollout.code]??rollout.code)||'每个目标独立核对，不使用其他探针的验证结果。'" class="section-gap" />
 <a-descriptions bordered :column="2" class="section-gap rollout-summary">
  <a-descriptions-item label="发布名称">{{rollout.spec.name}}</a-descriptions-item><a-descriptions-item label="当前批次">第 {{rollout.current_batch+1}} 批 · 共 {{rollout.targets?.length}} 台探针</a-descriptions-item>
  <a-descriptions-item label="发布规则摘要" :span="2"><span class="technical">{{rollout.package_sha256}}</span></a-descriptions-item>
  <a-descriptions-item label="批次设置">首批 {{rollout.spec.canary_count}} 台，之后每批 {{rollout.spec.batch_size}} 台</a-descriptions-item><a-descriptions-item label="观察时间">每批 {{rollout.spec.observation_seconds}} 秒</a-descriptions-item>
  <a-descriptions-item label="执行截止">{{formatTime(rollout.deadline)}}</a-descriptions-item><a-descriptions-item label="档案到期">{{formatTime(rollout.expires_at)}}</a-descriptions-item>
  <a-descriptions-item v-if="rollout.observation_started_at" label="当前观察起点" :span="2">{{formatTime(rollout.observation_started_at)}}</a-descriptions-item>
  <a-descriptions-item v-if="rollout.stop_reason" label="停止原因" :span="2">{{rollout.stop_reason}}</a-descriptions-item>
 </a-descriptions>
 <div v-if="!target" class="table-wrap"><a-table :columns="columns" :data-source="rollout.targets" :pagination="{pageSize:20,showSizeChanger:false,hideOnSinglePage:true}" row-key="ordinal" :scroll="{x:830}"><template #bodyCell="{column,record}">
  <template v-if="column.key==='sensor'"><span>{{record.spec.sensor_id}}</span><small class="record-id">{{record.batch===0?'首批':'第 '+(record.batch+1)+' 批'}}</small></template>
  <template v-else-if="column.key==='plan'"><span>{{record.spec.name}}</span><small class="record-id">批准修订 {{record.authorized_revision}} · {{record.spec.package_id}} / {{record.spec.package_revision}}</small></template>
  <template v-else-if="column.key==='state'"><a-tag :color="color(record.state)">{{targetStates[record.state]}}</a-tag><small class="record-id">{{record.run&&!record.run.finished_at?syncStates[record.run.state]:(rolloutCodes[record.code]??syncCodes[record.code]??record.code)}}</small></template>
  <template v-else-if="column.key==='action'"><a-button type="link" @click="inspect(record.ordinal)">验证证据</a-button></template>
 </template></a-table></div>
 <a-modal v-if="target" open title="目标验证证据" :width="760" :footer="null" @cancel="target=undefined">
  <a-descriptions bordered :column="1"><a-descriptions-item label="目标探针">{{target.spec.sensor_id}}</a-descriptions-item><a-descriptions-item label="注册代次"><span class="technical">{{target.spec.registration_id}}</span></a-descriptions-item><a-descriptions-item label="批准计划">{{target.plan_id}} · 修订 {{target.authorized_revision}}</a-descriptions-item><a-descriptions-item label="执行授权修订">{{target.execution_revision||'尚未启用'}}</a-descriptions-item><a-descriptions-item label="规则修订">{{target.spec.package_id}} · {{target.spec.package_revision}}</a-descriptions-item><a-descriptions-item label="正反样本"><span>{{target.spec.positive_sample_id}}</span><br>{{target.spec.negative_sample_id}}</a-descriptions-item></a-descriptions>
  <ol class="rollout-proof"><li v-for="(title,index) in stages" :key="title"><span>{{title}}</span><RouterLink v-if="target.run?.tasks[index]" :to="{path:taskPath??'/sensors',query:{view:'tasks',task:target.run.tasks[index]}}">查看独立任务</RouterLink><span v-else class="field-hint">尚未提交</span></li></ol>
  <p class="field-hint">验证记录绑定该设备和检测配置。发布回执及心跳核对不代表检测准确率、加密可见性或持续大流量性能通过。</p>
 </a-modal>
</template>
<style scoped>
.rollout-summary :deep(.ant-descriptions-item-content){overflow-wrap:anywhere;word-break:break-word}.record-id{display:block;margin-top:4px;color:var(--muted);overflow-wrap:anywhere}.rollout-proof{padding-left:24px;margin:12px 0}.rollout-proof li{padding:8px 0;display:flex;gap:20px;flex-wrap:wrap}.rollout-proof li>span:first-child{min-width:110px}
</style>
