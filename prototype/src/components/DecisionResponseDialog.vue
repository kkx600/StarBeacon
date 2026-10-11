<script setup lang="ts">
import {computed,reactive,ref} from 'vue'
import type {BusinessRecord} from '../models'
const props=defineProps<{record:BusinessRecord}>(),emit=defineEmits<{close:[]}>()
const form=reactive({sensor:'probe_example',connector:'connector_example',ttl:300,reason:'',confirmed:false})
const accepted=ref(false),error=ref('')
const qualified=computed(()=>props.record.status==='策略命中'&&props.record.action==='建议评估源 IP 封禁')
function submit(){if(!qualified.value||!form.confirmed||!form.reason.trim()||form.reason!==form.reason.trim()||[...form.reason].length>500||/\p{Cc}/u.test(form.reason)||!Number.isSafeInteger(form.ttl)||form.ttl<30||form.ttl>3600){error.value='请核对原候选、期限和依据，并明确确认。';return}error.value='';accepted.value=true}
</script>
<template>
 <a-modal :open="true" title="处置确认" :width="720" :footer="null" @cancel="emit('close')">
  <a-alert type="info" show-icon message="合成示例：本页面不访问工程服务、探针或设备。影子判断与人工授权分别记录。" class="page-notice"/>
  <a-descriptions :column="1" size="small" bordered><a-descriptions-item label="原评估">{{record.name}}</a-descriptions-item><a-descriptions-item label="策略 / 修订">{{record.policy}}</a-descriptions-item><a-descriptions-item label="源 IP / 自报分数">{{record.source}} / {{record.confidence}} · 未校准</a-descriptions-item></a-descriptions>
  <a-alert v-if="!qualified" class="page-notice" type="warning" show-icon message="本评估没有匹配的源 IP 封禁候选，不能确认处置。"/>
  <template v-else-if="accepted"><a-alert type="info" show-icon class="page-notice" message="示例授权只保存在当前弹窗。未创建签名任务，不证明设备或流量阻断。工程任务详情使用原任务标识独立读取，不受最近 200 项列表上限影响。"/><a-descriptions :column="1" bordered size="small"><a-descriptions-item label="探针 / 连接器">{{form.sensor}} / {{form.connector}}</a-descriptions-item><a-descriptions-item label="示例期限">{{form.ttl}} 秒</a-descriptions-item><a-descriptions-item label="操作依据">{{form.reason}}</a-descriptions-item><a-descriptions-item label="示例任务标识">task_example</a-descriptions-item><a-descriptions-item label="执行 / 记录期限">限时执行与 180 天记录留存分别呈现（示例）</a-descriptions-item><a-descriptions-item label="档案摘要">未提供实际档案；不生成虚构摘要</a-descriptions-item></a-descriptions><div class="proto-response-actions"><a-button @click="emit('close')">返回</a-button></div></template>
  <a-form v-else :model="form" layout="vertical" @finish="submit">
   <a-alert v-if="error" class="page-notice" type="error" show-icon :message="error"/>
   <a-form-item label="执行探针" required><a-select v-model:value="form.sensor" aria-label="处置执行探针" :options="[{value:'probe_example',label:'合成执行探针 · probe_example'}]"/></a-form-item>
   <div class="proto-response-grid"><a-form-item label="联动设备" required><a-select v-model:value="form.connector" aria-label="处置联动设备" :options="[{value:'connector_example',label:'合成 HTTP 联动设备'}]"/></a-form-item><a-form-item label="封禁期限（秒）" required><a-input-number v-model:value="form.ttl" aria-label="处置封禁期限" :min="30" :max="3600" :precision="0"/></a-form-item></div>
   <a-form-item label="操作依据" required><a-textarea v-model:value="form.reason" aria-label="处置操作依据" :auto-size="{minRows:2,maxRows:4}" :maxlength="500"/></a-form-item>
   <a-checkbox v-model:checked="form.confirmed">确认原评估源 IP 的限时封禁配置</a-checkbox>
   <p class="muted">工程提交须重新核对当前策略、本人研判、告警来源、探针注册与设备配置。默认保留 180 天，期限可配置；此处没有实际材料和设备资格。</p>
   <div class="proto-response-actions"><a-button type="primary" html-type="submit">确认并提交</a-button><a-button @click="emit('close')">返回</a-button></div>
  </a-form>
 </a-modal>
</template>
<style scoped>.proto-response-grid{display:grid;grid-template-columns:minmax(0,1fr) 170px;gap:12px}.proto-response-grid .ant-input-number{width:100%}.proto-response-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}.ant-form{margin-top:12px}@media(max-width:600px){.proto-response-grid{grid-template-columns:1fr}}</style>
