<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import type {PreviewState} from '../models'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
import RuleRolloutForm from '../../../web/platform/src/features/rules/RuleRolloutForm.vue'
import RuleRolloutDetail from '../../../web/platform/src/features/rules/RuleRolloutDetail.vue'
import type {RuleSyncPlan} from '../../../web/platform/src/features/rules/sync'
import {rolloutStates,type RuleRollout,type RolloutCreate} from '../../../web/platform/src/features/rules/rollout'
const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[state:PreviewState]}>()
const at='2026-10-18T01:00:00Z'
const plans:RuleSyncPlan[]=[0,1,2].map(i=>({id:'sync_example_'+i,revision:3,spec:{name:['办公网探针','研发网探针','数据中心探针'][i]+'（示例）',enabled:false,sensor_id:'sensor_example_'+i,registration_id:'registration_example_'+i,package_id:'rules_example',package_revision:5,positive_sample_id:'sample_positive',negative_sample_id:'sample_negative',interval_seconds:60},created_by:'admin_example',updated_at:at,next_at:at,processed_revision:2}))
const original:RuleRollout={id:'rollout_example',spec:{name:'办公与研发探针规则发布（示例）',plans:plans.map(p=>({plan_id:p.id,revision:p.revision})),canary_count:1,batch_size:2,observation_seconds:60,timeout_seconds:3600},created_by:'admin_example',state:'observing',code:'observing',current_batch:0,package_sha256:'b'.repeat(64),created_at:at,deadline:'2026-10-18T02:00:00Z',next_at:at,observation_started_at:'2026-10-18T01:05:30Z',expires_at:'2027-04-16T01:00:00Z',stop_reason:'',stopped_by:'',targets:plans.map((p,i)=>({ordinal:i,batch:i?1:0,plan_id:p.id,authorized_revision:3,execution_revision:i?0:4,spec:p.spec,state:i?'queued':'observing',code:i?'':'applied',...(i?{}:{run:{id:'sync_run_example',plan_revision:4,spec:{...p.spec,enabled:true},created_by:'admin_example',state:'succeeded',code:'applied',stage:3,tasks:['task_validation','task_positive','task_negative','task_apply'],expected_sha256:'c'.repeat(64),created_at:at,finished_at:'2026-10-18T01:05:20Z',expires_at:'2027-04-16T01:00:00Z'}})}))}
const record=shallowRef(original),editing=shallowRef(false),detail=shallowRef(false),submitted=shallowRef(false),draftEpoch=shallowRef(0)
watch(()=>props.state,s=>{editing.value=s==='action';detail.value=s==='detail';submitted.value=false},{immediate:true})
const items=computed(()=>props.state==='empty'?[]:[record.value])
const columns=[{title:'发布任务',key:'name',width:280},{title:'目标与批次',key:'scope',width:180},{title:'执行状态',key:'state',width:240},{title:'创建时间',key:'time',width:180},{title:'操作',key:'action',width:90}]
function save(c:RolloutCreate){record.value={...original,id:c.id,spec:c.spec,state:'pending',code:''};draftEpoch.value++;editing.value=false;detail.value=false;submitted.value=true;emit('state','data')}
</script>
<template>
 <PageHeader title="规则自动同步" description="固定目标与批准修订，逐台验证并分批发布。"><router-link to="/page/rule-sync"><a-button>单探针计划</a-button></router-link><a-button v-if="detail" @click="detail=false;emit('state','data')">返回列表</a-button><a-button v-else type="primary" @click="editing=true">创建分批发布</a-button></PageHeader>
 <a-alert type="info" show-icon message="以下为合成示例。原型不启用真实计划，不向探针下发任务；观察窗口、回执和设备身份仅用于展示业务状态。" class="section-gap" />
 <a-alert v-if="submitted" type="success" show-icon message="本地示例已保存，未提交设备任务。" class="section-gap" />
 <section class="panel"><StatePanel v-if="['empty','error','loading'].includes(state)" :state="state as 'empty'|'error'|'loading'" :title="state==='empty'?'暂无分批发布':undefined" :description="state==='empty'?'先创建停用的单探针同步计划，再选择固定修订并批准发布范围。':undefined" :action="state==='empty'?'创建分批发布':'重新加载'" @action="state==='empty'?editing=true:emit('state','data')" />
  <RuleRolloutDetail v-else-if="detail" :rollout="record" task-path="/page/rule-tests" />
  <a-table v-else :columns="columns" :data-source="items" row-key="id" :pagination="false" :scroll="{x:970}"><template #bodyCell="{column}"><template v-if="column.key==='name'"><a-button type="link" @click="detail=true">{{record.spec.name}}</a-button><small class="record-id technical">{{record.id}}</small></template><template v-else-if="column.key==='scope'">3 台探针<small class="record-id">首批 1 台 · 每批 2 台</small></template><template v-else-if="column.key==='state'"><a-tag color="processing">{{rolloutStates[record.state]}}</a-tag><small class="record-id">窗口结束后核对新的心跳与原生观测</small></template><template v-else-if="column.key==='time'">2026-10-18 09:00:00</template><template v-else-if="column.key==='action'"><a-button type="link" @click="detail=true">查看</a-button></template></template></a-table>
 </section>
 <RuleRolloutForm :key="draftEpoch" :open="editing" :plans="plans" user-id="admin_example" :busy="false" :locked="false" error="" :plans-pending="false" plans-error="" :has-more="false" @save="save" @close="editing=false" />
</template>
<style scoped>
.record-id{display:block;margin-top:4px;color:var(--muted);overflow-wrap:anywhere}.ant-btn-link{height:auto;padding:0;white-space:normal;text-align:left}
</style>
