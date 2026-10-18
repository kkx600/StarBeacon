<script setup lang="ts">
import {shallowRef} from 'vue'
import {Table as ATable,Tag as ATag,Modal as AModal} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import {useRuleRollouts} from './useRuleRollouts'
import {rolloutStates,rolloutCodes,rolloutTerminal,stopReasonError} from './rollout'
import RuleRolloutForm from './RuleRolloutForm.vue'
import RuleRolloutDetail from './RuleRolloutDetail.vue'
const state=useRuleRollouts(),reason=shallowRef(''),reasonError=shallowRef('')
const columns=[{title:'发布任务',key:'name',width:250},{title:'目标与批次',key:'scope',width:170},{title:'执行状态',key:'state',width:260},{title:'创建时间',key:'time',width:180},{title:'操作',key:'action',width:90}]
function stop(){reasonError.value=stopReasonError(reason.value);if(!reasonError.value)void state.stop(reason.value)}
function openStop(){reason.value='';reasonError.value='';state.openStop()}
</script>
<template>
 <div class="panel-header"><h2>{{state.detailID.value?'分批发布详情':'分批发布'}}</h2><a-space wrap><template v-if="state.detailID.value"><a-button @click="state.back">返回列表</a-button><a-button :loading="state.detailPending.value" @click="state.show(state.detailID.value)">刷新执行状态</a-button><a-button v-if="state.detail.value&&!rolloutTerminal(state.detail.value.state)&&state.detail.value.state!=='stopping'" danger :disabled="state.saving.value||!!state.unconfirmed.value" @click="openStop">停止后续发布</a-button></template><template v-else><a-button :loading="state.pending.value" @click="state.refresh">刷新</a-button><a-button type="primary" :disabled="state.saving.value||!!state.unconfirmed.value" @click="state.open">创建分批发布</a-button></template></a-space></div>
 <a-alert v-if="state.unconfirmed.value&&!state.creating.value&&!state.stopping.value" type="warning" show-icon message="上次操作结果尚未确认，请核对原提交。" class="section-gap"><template #action><a-button :loading="state.saving.value" @click="state.confirm">核对原提交</a-button></template></a-alert>
 <section class="panel">
  <StatePanel v-if="state.detailID.value" :loading="state.detailPending.value" :error="state.detailError.value" :empty="false" @retry="state.show(state.detailID.value)"><RuleRolloutDetail v-if="state.detail.value" :rollout="state.detail.value" /></StatePanel>
  <template v-else><a-alert type="info" show-icon message="每个目标独立验证，前一批发布后的心跳与观察窗口核对完成后，才会启用下一批。已执行的规则不会因停止而自动回滚。" class="section-gap" /><StatePanel :loading="state.pending.value" :error="state.error.value" :empty="state.page.value.items.length===0" description="暂无分批发布。先创建停用的单探针同步计划，再选择固定修订并批准发布范围。" @retry="state.refresh"><div class="table-wrap"><a-table :columns="columns" :data-source="state.page.value.items" :pagination="false" :scroll="{x:950}" row-key="id"><template #bodyCell="{column,record}">
   <template v-if="column.key==='name'"><button class="link-button" @click="state.show(record.id)">{{record.spec.name}}</button><small class="record-id technical">{{record.id}}</small></template>
   <template v-else-if="column.key==='scope'">{{record.spec.plans.length}} 台探针<small class="record-id">首批 {{record.spec.canary_count}} 台 · 每批 {{record.spec.batch_size}} 台</small></template>
   <template v-else-if="column.key==='state'"><a-tag :color="record.state==='succeeded'?'success':record.state==='blocked'?'error':record.state==='stopped'?'warning':'processing'">{{rolloutStates[record.state]}}</a-tag><small class="record-id">{{rolloutCodes[record.code]??record.code}}</small></template>
   <template v-else-if="column.key==='time'">{{formatTime(record.created_at)}}</template>
   <template v-else-if="column.key==='action'"><a-button type="link" @click="state.show(record.id)">查看</a-button></template>
  </template></a-table></div></StatePanel><div class="rollout-pagination"><a-button :disabled="state.pending.value||state.cursors.value.length<2" @click="state.previous">上一页</a-button><span>第 {{state.cursors.value.length}} 页</span><a-button :disabled="state.pending.value||!state.page.value.next_cursor" @click="state.next">下一页</a-button></div></template>
 </section>
 <RuleRolloutForm v-if="state.creating.value" :plans="state.plans.value" :user-id="session.current.value?.id??''" :busy="state.saving.value" :locked="!!state.unconfirmed.value" :error="state.formError.value" :plans-pending="state.plansPending.value" :plans-error="state.plansError.value" :has-more="!!state.plansCursor.value" @save="state.create" @confirm="state.confirm" @close="state.close" @more="state.loadPlans(true)" @retry="state.loadPlans()" />
 <a-modal v-if="state.stopping.value" open title="停止后续发布" :width="560" :mask-closable="false" :closable="!state.saving.value" :keyboard="!state.saving.value" @cancel="state.close">
  <a-alert type="warning" show-icon message="停止提交后续任务，并等待已下发任务的独立回执。已经生效的规则继续保留，回退需要另行验证与授权。" class="section-gap" />
  <a-alert v-if="state.formError.value||reasonError" type="error" show-icon :message="state.formError.value||reasonError" class="section-gap" />
  <a-form layout="vertical"><a-form-item label="停止原因" required><a-textarea v-model:value="reason" :maxlength="512" :disabled="state.saving.value||!!state.unconfirmed.value" :auto-size="{minRows:3,maxRows:6}" aria-label="停止原因" @input="reasonError=''" /></a-form-item></a-form>
  <template #footer><a-button :disabled="state.saving.value" @click="state.close">关闭</a-button><a-button v-if="state.unconfirmed.value" type="primary" :loading="state.saving.value" @click="state.confirm">核对原提交</a-button><a-button v-else danger :loading="state.saving.value" @click="stop">确认停止后续发布</a-button></template>
 </a-modal>
</template>
<style scoped>
.rollout-pagination{display:flex;justify-content:flex-end;align-items:center;gap:12px;padding:12px}
</style>
