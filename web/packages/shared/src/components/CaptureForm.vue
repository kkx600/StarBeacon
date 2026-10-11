<script setup lang="ts">
import { Select as ASelect, InputNumber as AInputNumber, Checkbox as ACheckbox, Descriptions as ADescriptions } from 'ant-design-vue'
import { computed, reactive, watch } from 'vue'
import type { NetworkInterface, CaptureConfig, CaptureSettings } from '@starbeacon/shared/types.ts'
import { captureStates, captureErrors, formatTime } from '@starbeacon/shared/types.ts'
import { formatBytes } from '@starbeacon/shared/utils/format.ts'
const ADescriptionsItem=ADescriptions.Item
const props = withDefaults(defineProps<{interfaces:NetworkInterface[];capture:CaptureConfig;saving:boolean;scope?:'local'|'platform'}>(),{scope:'local'})
const emit = defineEmits<{save:[settings:CaptureSettings]}>()
const form = reactive({interfaces:[] as string[],threads:1,bpf_filter:'',promiscuous:true,confirmStop:false})
watch(() => JSON.stringify([props.capture.revision,props.capture.interfaces,props.capture.threads,props.capture.bpf_filter,props.capture.promiscuous]), () => {const value=props.capture;form.interfaces=[...value.interfaces];form.threads=value.threads??1;form.bpf_filter=value.bpf_filter??'';form.promiscuous=value.promiscuous??true;form.confirmStop=false},{immediate:true})
const isEthernet = (i:NetworkInterface) => /^(?:[\da-f]{2}:){5}[\da-f]{2}$/i.test(i.mac)
const options = computed(() => props.interfaces.map(i=>({value:i.name,label:`${i.name}${i.loopback?'（回环）':!i.up?'（关闭）':!isEthernet(i)?'（非 Ethernet）':''}`,disabled:i.loopback||!i.up||!isEthernet(i)})))
const stopping = computed(() => props.capture.managed && !!props.capture.applied_settings?.interfaces.length && form.interfaces.length===0)
const invalid = computed(() => !Number.isInteger(form.threads)||form.threads<1||form.threads>64||form.interfaces.length>16||new Set(form.interfaces).size!==form.interfaces.length||form.interfaces.length*form.threads>128||new TextEncoder().encode(form.bpf_filter).length>2048||/[\r\n\0]/.test(form.bpf_filter)||form.interfaces.some(name=>!props.interfaces.some(i=>i.name===name&&i.up&&!i.loopback&&isEthernet(i))))
const errorText = computed(() => props.capture.error_code ? captureErrors[props.capture.error_code]??'实际采集状态需要核对' : '')
function submit(){if(props.saving||invalid.value||(stopping.value&&!form.confirmStop))return;emit('save',{interfaces:[...form.interfaces],threads:form.threads,bpf_filter:form.bpf_filter.trim(),promiscuous:form.promiscuous})}
</script>
<template>
  <a-alert v-if="scope==='platform'" type="info" message="配置经平台签名后下发，设备会核对本机网卡及配置修订。应用配置会重启检测进程，可能出现采集间隙；执行结果以任务回执为准。" show-icon />
  <a-alert v-else-if="!capture.managed" type="info" message="当前读取外部 EVE 文件。保存仅登记采集目标；部署时启用托管采集后，设备才会根据所选网卡运行检测引擎。" show-icon />
  <a-alert v-else type="info" message="旁路采集使用 AF_PACKET。应用配置会重启检测进程，期间可能出现采集间隙；请在维护窗口操作。" show-icon />
  <a-alert v-if="errorText" class="section-gap" type="warning" :message="errorText" show-icon />
  <a-descriptions class="section-gap" size="small" :column="2" bordered>
    <a-descriptions-item label="实际状态">{{ captureStates[capture.status] }}</a-descriptions-item>
    <a-descriptions-item label="生效网卡">{{ capture.applied_settings?.interfaces.join('、') || '未采集' }}</a-descriptions-item>
    <a-descriptions-item v-if="capture.managed" label="配置修订">期望 {{ capture.revision??0 }} / 生效 {{ capture.applied_revision??0 }}</a-descriptions-item>
    <a-descriptions-item v-if="capture.managed" label="观测时间">{{ formatTime(capture.observed_at) }}</a-descriptions-item>
    <a-descriptions-item v-if="capture.counters" label="引擎累计流量">{{ capture.counters['decoder.bytes']===undefined?'尚未观测':formatBytes(capture.counters['decoder.bytes']) }}</a-descriptions-item>
    <a-descriptions-item v-if="capture.counters" label="内核丢包">{{ capture.counters['capture.kernel_drops']??'尚未观测' }}</a-descriptions-item>
    <a-descriptions-item v-if="capture.counters_observed_at" label="计数观测时间">{{ formatTime(capture.counters_observed_at) }}</a-descriptions-item>
    <a-descriptions-item v-if="capture.spool_budget" label="EVE 缓冲占用">{{ formatBytes(capture.spool_bytes) }} / {{ formatBytes(capture.spool_budget) }}</a-descriptions-item>
    <a-descriptions-item v-if="capture.rotation_pending" label="来源轮转">旧来源正在等待持久排空，期间继续保留缓冲文件</a-descriptions-item>
  </a-descriptions>
  <a-form layout="vertical" :model="form" class="capture-form" @finish="submit">
    <a-form-item label="镜像采集网卡" html-for="capture-interfaces"><a-select id="capture-interfaces" aria-label="镜像采集网卡" v-model:value="form.interfaces" mode="multiple" :options="options" placeholder="选择已启用的非回环 Ethernet 接口" :disabled="saving" /></a-form-item>
    <div class="capture-fields"><a-form-item label="每个网卡的检测线程" html-for="capture-threads"><a-input-number id="capture-threads" aria-label="每个网卡的检测线程" v-model:value="form.threads" :min="1" :max="64" :precision="0" :disabled="saving" /></a-form-item><a-form-item label="混杂模式"><a-checkbox v-model:checked="form.promiscuous" :disabled="saving">接收镜像口可见的全部帧</a-checkbox></a-form-item></div>
    <a-form-item label="BPF 捕获过滤器" html-for="capture-bpf" extra="留空表示不按 BPF 排除流量。过滤器会影响检测可见范围，不能代替告警筛选。"><a-input id="capture-bpf" aria-label="BPF 捕获过滤器" v-model:value="form.bpf_filter" :maxlength="2048" placeholder="例如：tcp port 80 or tcp port 443" :disabled="saving" /></a-form-item>
    <a-alert v-if="invalid" type="error" message="请核对网卡、过滤器及线程数量；单网卡支持 1–64 个线程，总计不超过 128。" show-icon class="section-gap" />
    <a-checkbox v-if="stopping" v-model:checked="form.confirmStop" :disabled="saving" class="section-gap">确认停止当前采集，停止后不会产生新的网络检测告警</a-checkbox>
    <a-button type="primary" html-type="submit" :loading="saving" :disabled="invalid||(stopping&&!form.confirmStop)">{{ scope==='platform'?(stopping?'下发停止采集':'下发采集配置'):!capture.managed?'保存采集目标':stopping?'停止采集':'应用采集配置' }}</a-button>
  </a-form>
</template>
<style scoped>
.capture-fields{display:grid;grid-template-columns:minmax(160px,1fr) minmax(240px,2fr);gap:12px}.capture-form{max-width:880px}.capture-form .ant-input-number{width:100%}@media(max-width:1100px){.capture-fields{grid-template-columns:1fr}}
</style>
