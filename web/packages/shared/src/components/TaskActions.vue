<script setup lang="ts">
import {Popconfirm as APopconfirm} from 'ant-design-vue'
import type {SensorTask} from '../types'
defineProps<{task:SensorTask;cancellable?:boolean;reconcilable?:boolean;responseable?:boolean;saving?:boolean;local?:boolean}>()
const emit=defineEmits<{cancel:[task:SensorTask];reconcile:[task:SensorTask];response:[task:SensorTask,kind:'response.read'|'response.revoke']}>()
</script>
<template>
 <a-space>
  <template v-if="responseable&&!local&&task.kind==='response.block'&&task.response_action&&task.delivery_count>0&&['succeeded','unknown','failed'].includes(task.state)">
   <a-button type="link" :disabled="saving" @click="emit('response',task,'response.read')">回读</a-button>
   <a-popconfirm :title="'解除原封禁任务的独立租约？目标 '+task.response_action.target_ip+'；其他租约保持有效。'" ok-text="提交解除" cancel-text="取消" @confirm="emit('response',task,'response.revoke')"><a-button type="link" :disabled="saving">解除</a-button></a-popconfirm>
  </template>
  <a-popconfirm v-if="cancellable&&task.state==='queued'&&task.delivery_count===0" title="取消尚未投递的任务？已投递任务需等待设备回执。" ok-text="确定" cancel-text="取消" @confirm="emit('cancel',task)"><a-button type="link" :disabled="saving">取消</a-button></a-popconfirm>
  <a-popconfirm v-if="reconcilable&&!local&&task.kind==='rules.apply'&&task.state==='unknown'&&!task.rule_resolution" title="重新装载当前登记规则，回读引擎后保存核实结果。" ok-text="提交核实" cancel-text="取消" @confirm="emit('reconcile',task)"><a-button type="link" :disabled="saving">核实规则</a-button></a-popconfirm>
 </a-space>
</template>
