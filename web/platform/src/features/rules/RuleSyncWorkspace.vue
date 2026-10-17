<script setup lang="ts">
import {shallowRef} from 'vue'
import {Table as ATable,Modal as AModal,Tag as ATag,Descriptions as ADescriptions,DescriptionsItem as ADescriptionsItem} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {useRuleSync} from './useRuleSync'
import RuleSyncForm from './RuleSyncForm.vue'
import {syncStates,syncCodes,type RuleSyncPlan} from './sync'
const state=useRuleSync(),detail=shallowRef<RuleSyncPlan>()
const columns=[{title:'计划 / 探针',key:'name',width:240},{title:'批准规则',key:'package',width:220},{title:'状态',key:'state',width:170},{title:'最近更新',key:'time',width:180},{title:'操作',key:'action',width:160}]
const stages=['装载检查','正样本重放','反样本重放','规则发布']
function showDetail(id:string){detail.value=state.page.value.items.find(p=>p.id===id)}
function configure(id:string){const p=state.page.value.items.find(p=>p.id===id);if(p)void state.open(p)}
</script>
<template>
 <div class="panel-header"><h2>规则自动同步</h2><a-space><a-button :loading="state.pending.value" @click="state.refresh">刷新</a-button><a-button type="primary" :disabled="state.saving.value||!!state.unconfirmed.value" @click="state.open(null)">创建同步计划</a-button></a-space></div>
 <a-alert type="info" show-icon message="批准固定修订后，由平台持续核对并通过采集器执行。未知结果需要独立核实；停用不撤销已经下发的任务。" class="section-gap" />
 <a-alert v-if="state.unconfirmed.value&&state.editing.value===undefined" type="warning" show-icon message="上次保存结果尚未确认，请核对原提交。" class="section-gap"><template #action><a-button :loading="state.saving.value" @click="state.confirm">核对原提交</a-button></template></a-alert>
 <section class="panel"><StatePanel :loading="state.pending.value" :error="state.error.value" :empty="state.page.value.items.length===0" description="暂无规则同步计划。创建计划前，请导入正反样本并核对探针执行能力。" @retry="state.refresh">
  <div class="table-wrap"><a-table :columns="columns" :data-source="state.page.value.items" :pagination="false" :scroll="{x:970}" row-key="id"><template #bodyCell="{column,record}">
   <template v-if="column.key==='name'"><button class="link-button" @click="showDetail(record.id)">{{record.spec.name}}</button><small class="record-id technical">{{record.spec.sensor_id}}</small></template>
   <template v-else-if="column.key==='package'"><span>{{record.spec.package_id}}</span><small class="record-id">修订 {{record.spec.package_revision}} · 授权修订 {{record.revision}}</small></template>
   <template v-else-if="column.key==='state'"><a-tag :color="record.spec.enabled?'blue':'default'">{{record.spec.enabled?'启用':'停用'}}</a-tag><small class="record-id">{{record.run?syncStates[record.run.state]:record.processed_revision?'运行档案已到期':'等待核对'}}</small></template>
   <template v-else-if="column.key==='time'">{{formatTime(record.updated_at)}}</template>
   <template v-else-if="column.key==='action'"><a-button type="link" @click="showDetail(record.id)">查看</a-button><a-button type="link" :disabled="state.saving.value||!!state.unconfirmed.value" @click="configure(record.id)">配置</a-button></template>
  </template></a-table></div>
 </StatePanel><div class="sync-pagination"><a-button :disabled="state.pending.value||state.cursors.value.length<2" @click="state.previous">上一页</a-button><span>第 {{state.cursors.value.length}} 页</span><a-button :disabled="state.pending.value||!state.page.value.next_cursor" @click="state.next">下一页</a-button></div></section>
 <RuleSyncForm v-if="state.editing.value!==undefined" :key="state.editing.value?.id??'create'" :plan="state.editing.value" :sensors="state.sensors.value" :packages="state.packages.value" :busy="state.saving.value" :locked="!!state.unconfirmed.value" :error="state.formError.value" :choices-error="state.choicesError.value" :choices-pending="state.choicesPending.value" @save="state.save" @confirm="state.confirm" @close="state.close" />
 <a-modal v-if="detail" open title="规则同步详情" :width="780" :footer="null" @cancel="detail=undefined">
  <a-descriptions bordered :column="1"><a-descriptions-item label="计划">{{detail.spec.name}} · 授权修订 {{detail.revision}}</a-descriptions-item><a-descriptions-item label="探针">{{detail.spec.sensor_id}}</a-descriptions-item><a-descriptions-item label="注册代次"><span class="technical">{{detail.spec.registration_id}}</span></a-descriptions-item><a-descriptions-item label="批准规则">{{detail.spec.package_id}} · 修订 {{detail.spec.package_revision}}</a-descriptions-item><a-descriptions-item label="核对周期">{{detail.spec.interval_seconds}} 秒</a-descriptions-item></a-descriptions>
  <template v-if="detail.run"><p>本次批准规则：{{detail.run.spec.package_id}} · 修订 {{detail.run.spec.package_revision}}；批准人：{{detail.run.created_by}}</p><p>{{syncStates[detail.run.state]}} · {{syncCodes[detail.run.code]??detail.run.code}}（授权修订 {{detail.run.plan_revision}}）</p><ol class="sync-steps"><li v-for="(title,index) in stages" :key="title"><span>{{title}}</span><RouterLink v-if="detail.run.tasks[index]" :to="{path:'/sensors',query:{view:'tasks',task:detail.run.tasks[index]}}">查看独立任务</RouterLink><span v-else class="field-hint">尚未提交</span></li></ol><p class="field-hint">运行档案到期：{{formatTime(detail.run.expires_at)}}。生效回执反映执行时的状态，不代表此后规则未被其他授权操作改变。</p></template>
  <p v-else class="field-hint">{{detail.processed_revision?'本授权已处理，运行档案已超过保留期限。':'尚无运行记录。启用后会核对目标身份和执行条件。'}}</p>
 </a-modal>
</template>
<style scoped>
.sync-pagination{display:flex;align-items:center;justify-content:flex-end;gap:12px;padding:12px}.sync-steps{padding-left:24px}.sync-steps li{padding:10px 0}.sync-steps li>span:first-child{display:inline-block;min-width:130px}
</style>
