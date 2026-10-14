<script setup lang="ts">
import {computed} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import type {AppSnapshot,AppTarget} from './applicationDeployment'
const props=defineProps<{pending:boolean;busy:boolean;unconfirmed:boolean;error:string;targets:readonly AppTarget[];snapshot:AppSnapshot|null;selected:string;taskId:string}>()
const emit=defineEmits<{close:[];refresh:[];choose:[id:string];submit:[];confirm:[];task:[id:string]}>()
const options=computed(()=>props.targets.map(row=>({value:row.id,label:`${row.name} · ${row.id}`})))
const target=computed(()=>props.targets.find(row=>row.id===props.selected))
</script>
<template>
 <a-modal :open="true" title="部署应用识别规则" :width="720" :footer="null" :closable="!busy" :mask-closable="!busy&&!unconfirmed" :keyboard="!busy&&!unconfirmed" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="emit('close')">
  <a-alert type="info" show-icon message="将本租户启用规则的完整快照下发到指定探针。分类仅使用可见协议元数据，不执行网络阻断，也不改写历史事件。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="提交结果尚未确认，探针与规则快照已锁定。关闭后可重新打开核对原提交。" class="section-gap"/>
  <a-alert v-if="taskId" type="success" show-icon message="应用规则部署已受理，实际生效状态以采集器任务回执为准。" class="section-gap"/>
  <StatePanel :loading="pending" :error="error" @retry="unconfirmed?emit('confirm'):emit('refresh')">
   <template v-if="snapshot">
    <a-alert v-if="snapshot.versions.length===0" type="warning" show-icon message="当前启用规则为空。部署空快照会清空目标探针的应用识别规则，后续协议事件将保持未知。" class="section-gap"/>
    <label for="application-deployment-target">目标探针</label>
    <a-select id="application-deployment-target" :value="selected||undefined" :options="options" :disabled="busy||unconfirmed||!!taskId" :show-search="true" option-filter-prop="label" placeholder="选择在线且支持应用规则部署的探针" class="deployment-select" @update:value="emit('choose',String($event))"/>
    <p v-if="!targets.length" class="muted">没有符合条件的在线探针。请核对采集器版本、任务信任与最近状态观测。</p>
    <dl class="deployment-facts"><dt>部署规则</dt><dd>{{snapshot.versions.length}} 条当前启用规则</dd><dt>快照 SHA-256</dt><dd class="technical">{{snapshot.rules_sha256}}</dd><template v-if="target"><dt>注册身份</dt><dd class="technical">{{target.registration_id}}</dd><dt>当前部署</dt><dd>{{target.state.deployment_id||'尚未部署'}} · {{target.state.rule_count}} 条</dd><dt>观测时间</dt><dd>{{formatTime(target.observed_at)}}</dd></template></dl>
   </template>
  </StatePanel>
  <div class="deployment-actions"><a-button :disabled="pending||busy||unconfirmed" @click="emit('refresh')">刷新规则与探针</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else-if="taskId" type="primary" @click="emit('task',taskId)">查看执行回执</a-button><a-button v-else type="primary" :loading="busy" :disabled="pending||!snapshot||!selected||!!error" @click="emit('submit')">提交部署</a-button></div>
 </a-modal>
</template>
<style scoped>
.deployment-select{width:100%;margin-top:8px}.deployment-facts{display:grid;grid-template-columns:120px minmax(0,1fr);gap:8px;margin:12px 0}.deployment-facts dt{color:var(--text-secondary,#4b5563)}.deployment-facts dd{margin:0;overflow-wrap:anywhere}.deployment-actions{display:flex;justify-content:flex-end;flex-wrap:wrap;gap:8px;margin-top:12px}.technical{overflow-wrap:anywhere}
</style>
