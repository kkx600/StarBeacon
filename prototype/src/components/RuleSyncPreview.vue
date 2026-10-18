<script setup lang="ts">
import {useFeedback} from '../../../web/packages/shared/src/composables/useFeedback'
import {computed,shallowRef,watch} from 'vue'
import type {Sensor} from '../../../web/packages/shared/src/types'
import type {PreviewState} from '../models'
import type {RuleSyncChange,RuleSyncPlan} from '../../../web/platform/src/features/rules/sync'
import {syncStates,syncCodes} from '../../../web/platform/src/features/rules/sync'
import RuleSyncForm from '../../../web/platform/src/features/rules/RuleSyncForm.vue'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
const message=useFeedback()
const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>()
const at='2026-10-17T01:00:00Z'
const example:RuleSyncPlan={id:'sync_example',revision:2,spec:{name:'办公网规则同步（示例）',enabled:true,sensor_id:'sensor_example',registration_id:'registration_example',package_id:'rules_example',package_revision:3,positive_sample_id:'sample_positive',negative_sample_id:'sample_negative',interval_seconds:60},created_by:'admin_example',updated_at:at,next_at:at,processed_revision:1,run:{id:'sync_run_example',plan_revision:2,spec:{name:'办公网规则同步（示例）',enabled:true,sensor_id:'sensor_example',registration_id:'registration_example',package_id:'rules_example',package_revision:3,positive_sample_id:'sample_positive',negative_sample_id:'sample_negative',interval_seconds:60},created_by:'admin_example',state:'positive_replay',code:'',stage:1,tasks:['task_validation','task_positive','',''],expected_sha256:'a'.repeat(64),created_at:at,expires_at:'2027-04-15T01:00:00Z'}}
const records=shallowRef<RuleSyncPlan[]>([example]),editing=shallowRef<RuleSyncPlan|null|undefined>(),detail=shallowRef<RuleSyncPlan>()
const sensors=[{id:'sensor_example',name:'办公网探针（示例）',registration_id:'registration_example',active:true,status:'online',health:{},created_at:at,last_seen:at}] as Sensor[]
const packages=[{id:'rules_example',name:'办公网检测规则（示例）',revision:3,engine_version:'8.0.7',sha256:'b'.repeat(64),created_at:at}]
const items=computed(()=>props.state==='empty'?[]:records.value)
const columns=[{title:'计划 / 探针',key:'name',width:240},{title:'批准规则',key:'package',width:220},{title:'状态',key:'state',width:170},{title:'最近更新',key:'time',width:180},{title:'操作',key:'action',width:160}]
watch(()=>props.state,state=>{editing.value=state==='action'?null:undefined;detail.value=state==='detail'?records.value[0]:undefined},{immediate:true})
function save(c:RuleSyncChange){records.value=[{id:c.id,revision:c.expected_revision+1,spec:c.spec,created_by:'admin_example',updated_at:at,next_at:at,processed_revision:0}];editing.value=undefined;emit('state','data');message.success('计划已保存为本地示例，未提交设备任务')}
</script>
<template>
 <PageHeader title="规则自动同步" description="管理批准规则修订的同步计划，核对各阶段独立任务与实际执行结果。"><router-link to="/page/rule-sync?mode=rollouts&amp;state=data"><a-button>分批发布</a-button></router-link><a-button @click="emit('state','data')">刷新</a-button><a-button type="primary" @click="editing=null">创建同步计划</a-button></PageHeader>
 <a-alert type="info" show-icon message="本页面为合成示例。计划绑定指定规则修订、样本和探针注册代次，不跟随未批准修订；原型不向真实设备下发任务。" class="section-gap" />
 <section class="panel"><StatePanel v-if="['empty','error','loading'].includes(state)" :state="state as 'empty'|'error'|'loading'" :title="state==='empty'?'暂无规则同步计划':undefined" :description="state==='empty'?'创建计划前，请导入正反样本并核对探针执行能力。':undefined" :action="state==='empty'?'创建同步计划':'重新加载'" @action="state==='empty'?editing=null:emit('state','data')" />
 <a-table v-else :columns="columns" :data-source="items" row-key="id" :pagination="false" :scroll="{x:970}"><template #bodyCell="{column,record}"><template v-if="column.key==='name'"><a-button type="link" @click="detail=record">{{record.spec.name}}</a-button><small class="record-id">{{record.spec.sensor_id}}</small></template><template v-else-if="column.key==='package'">{{record.spec.package_id}}<small class="record-id">修订 {{record.spec.package_revision}} · 授权修订 {{record.revision}}</small></template><template v-else-if="column.key==='state'"><a-tag :color="record.spec.enabled?'blue':'default'">{{record.spec.enabled?'启用':'停用'}}</a-tag><small class="record-id">{{record.run?syncStates[record.run.state]:'等待核对'}}</small></template><template v-else-if="column.key==='time'">2026-10-17 09:00:00</template><template v-else-if="column.key==='action'"><a-button type="link" @click="detail=record">查看</a-button><a-button type="link" @click="editing=record">配置</a-button></template></template></a-table></section>
 <RuleSyncForm v-if="editing!==undefined" :key="editing?.id??'create'" :plan="editing" :sensors="sensors" :packages="packages" :busy="false" :locked="false" error="" choices-error="" :choices-pending="false" @save="save" @close="editing=undefined" />
 <a-modal v-if="detail" open title="规则同步详情" :footer="null" :width="780" @cancel="detail=undefined"><a-alert type="info" show-icon message="合成执行记录，不代表真实引擎已验证或已生效。" class="section-gap" /><a-descriptions bordered :column="1"><a-descriptions-item label="计划">{{detail.spec.name}} · 授权修订 {{detail.revision}}</a-descriptions-item><a-descriptions-item label="探针">{{detail.spec.sensor_id}}</a-descriptions-item><a-descriptions-item label="注册代次">{{detail.spec.registration_id}}</a-descriptions-item><a-descriptions-item label="批准规则">{{detail.spec.package_id}} · 修订 {{detail.spec.package_revision}}</a-descriptions-item><a-descriptions-item label="核对周期">{{detail.spec.interval_seconds}} 秒</a-descriptions-item></a-descriptions><template v-if="detail.run"><p>本次批准规则：{{detail.run.spec.package_id}} · 修订 {{detail.run.spec.package_revision}}；批准人：{{detail.run.created_by}}</p><p>{{syncStates[detail.run.state]}} · {{syncCodes[detail.run.code]??'等待独立任务回执'}}</p><ol class="plain-list"><li v-for="(label,index) in ['装载检查','正样本重放','反样本重放','规则发布']" :key="label">{{label}}：{{detail.run.tasks[index]||'尚未提交'}}</li></ol><p class="field-hint">停用计划停止后续步骤，已经下发的任务仍需核对独立结果。运行档案默认保留 180 天。</p></template></a-modal>
</template>

<style scoped>
.record-id{display:block;margin-top:4px;color:var(--muted);overflow-wrap:anywhere}.ant-btn-link{height:auto;padding:0;white-space:normal;text-align:left}
</style>
