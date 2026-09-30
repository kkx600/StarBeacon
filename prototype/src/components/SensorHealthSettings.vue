<script setup lang="ts">
import {reactive,ref} from 'vue'
import {message} from 'ant-design-vue'
import {sensorThresholds} from '../composables/useSensorHealth'
import {defaultSensorThresholds,type SensorThresholds} from '../data/sensorHealth'
const open=ref(false)
const draft=reactive({...sensorThresholds})
const error=ref('')
const fields:{key:keyof SensorThresholds;label:string;suffix:string;min:number;max:number;step:number}[]=[
  {key:'cpu',label:'CPU 使用率',suffix:'%',min:1,max:100,step:1},
  {key:'memory',label:'内存使用率',suffix:'%',min:1,max:100,step:1},
  {key:'disk',label:'磁盘使用率',suffix:'%',min:1,max:100,step:1},
  {key:'drop',label:'丢包率',suffix:'%',min:0.01,max:100,step:0.01},
  {key:'heartbeat',label:'心跳超时',suffix:'秒',min:30,max:3600,step:30},
]
function edit(){Object.assign(draft,sensorThresholds);error.value='';open.value=true}
function save(){
  const invalid=fields.find(field=>typeof draft[field.key]!=='number'||!Number.isFinite(draft[field.key])||draft[field.key]<field.min||draft[field.key]>field.max)
  if(invalid){error.value=`${invalid.label}需为 ${invalid.min}–${invalid.max}${invalid.suffix}。`;return}
  Object.assign(sensorThresholds,draft);open.value=false;message.success('健康阈值已保存至当前原型会话。')
}
</script>
<template>
  <a-button @click="edit">健康阈值</a-button>
  <a-modal v-model:open="open" title="探针健康阈值" :width="560" ok-text="保存" cancel-text="取消" @ok="save">
    <p class="muted">资源或丢包达到阈值时标记需要关注；心跳超过期限时，当前遥测不可观测。</p>
    <a-form layout="vertical"><a-form-item v-for="field in fields" :key="field.key" :label="field.label"><a-input-number v-model:value="draft[field.key]" :aria-label="field.label" :min="field.min" :max="field.max" :step="field.step" style="width:100%"><template #addonAfter>{{field.suffix}}</template></a-input-number></a-form-item></a-form>
    <a-alert v-if="error" :message="error" type="error" show-icon/>
    <div class="threshold-footer"><a-button type="link" @click="Object.assign(draft,defaultSensorThresholds)">恢复默认值</a-button><small class="muted">仅保存当前原型会话，不向探针下发配置。</small></div>
  </a-modal>
</template>
