<script setup lang="ts">
import {computed} from 'vue'
import {Select as ASelect,InputNumber as AInputNumber,Checkbox as ACheckbox} from 'ant-design-vue'
import type {ResponseConnector} from '../response'
const props=defineProps<{model:{connector_id:string;target_ip:string;ttl_seconds:number;reason:string;confirmed:boolean};connectors:ResponseConnector[];locked:boolean;saving:boolean;unconfirmed:boolean;fixed?:boolean}>()
const emit=defineEmits<{submit:[];close:[]}>()
const current=computed(()=>props.connectors.find(v=>v.connector_id===props.model.connector_id))
</script>
<template><a-form :model="model" layout="vertical" @finish="emit('submit')">
 <a-form-item label="联动设备" html-for="response-block-device" required><a-select id="response-block-device" v-model:value="model.connector_id" aria-label="联动设备" :disabled="locked||fixed" :options="connectors.map(v=>({value:v.connector_id,label:v.device_id+' · '+v.version}))"/></a-form-item>
 <div class="response-form-grid"><a-form-item label="目标 IP" html-for="response-block-target" required><a-input id="response-block-target" v-model:value="model.target_ip" aria-label="封禁目标 IP" :maxlength="45" :disabled="locked" placeholder="单个 IPv4 或 IPv6 地址"/></a-form-item><a-form-item label="封禁期限（秒）" html-for="response-block-ttl" required><a-input-number id="response-block-ttl" v-model:value="model.ttl_seconds" aria-label="封禁期限" :min="30" :max="current?.max_ttl_seconds??30" :precision="0" :disabled="locked"/></a-form-item></div>
 <a-form-item label="操作依据" html-for="response-block-reason" required><a-textarea id="response-block-reason" v-model:value="model.reason" aria-label="联动操作依据" :maxlength="500" :auto-size="{minRows:2,maxRows:4}" :disabled="locked"/></a-form-item>
 <a-checkbox v-model:checked="model.confirmed" :disabled="locked">确认提交此 IP 的限时封禁配置</a-checkbox>
 <p class="page-description section-gap">设备保护范围由采集器再次校验。任务投递期限与设备封禁到期时间分别记录；旁路探针自身不阻断流量。</p>
 <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="saving">{{unconfirmed?'核对原提交':'提交任务'}}</a-button><a-button :disabled="locked" @click="emit('close')">返回</a-button></div>
</a-form></template>
<style scoped>.response-form-grid{display:grid;grid-template-columns:1fr 170px;gap:var(--related-gap)}.response-form-grid .ant-input-number{width:100%}@media(max-width:600px){.response-form-grid{grid-template-columns:1fr}}</style>
