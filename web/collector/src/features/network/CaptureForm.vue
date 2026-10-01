<script setup lang="ts">
import { Select as ASelect } from 'ant-design-vue'
import { computed,reactive,watch } from 'vue'
import type { NetworkInterface,CaptureConfig } from '@starbeacon/shared/types.ts'
const props=defineProps<{interfaces:NetworkInterface[];capture:CaptureConfig;saving:boolean}>()
const emit=defineEmits<{save:[interfaces:string[]]}>()
const form=reactive({interfaces:[] as string[]})
watch(()=>props.capture,value=>{form.interfaces=[...value.interfaces]},{immediate:true})
const options=computed(()=>props.interfaces.map(i=>({value:i.name,label:`${i.name}${i.loopback?'（回环）':!i.up?'（关闭）':''}`,disabled:i.loopback||!i.up})))
</script>
<template>
  <a-alert type="info" message="保存仅更新采集目标，尚未应用到 Suricata。当前代理读取已配置的 EVE 文件，不执行网卡或管理网络变更。" show-icon />
  <a-form layout="vertical" :model="form" class="capture-form" @finish="emit('save',[...form.interfaces])"><a-form-item label="镜像采集网卡"><a-select v-model:value="form.interfaces" mode="multiple" :options="options" placeholder="选择已启用的非回环接口" :disabled="saving" /></a-form-item><a-space><a-button type="primary" html-type="submit" :loading="saving">保存采集目标</a-button><span class="status status-unknown">待应用</span></a-space></a-form>
</template>
