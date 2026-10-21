<script setup lang="ts">
import {Descriptions as ADescriptions,DescriptionsItem as ADescriptionsItem,Modal as AModal} from 'ant-design-vue'
import type {ConfigCheck} from '../responseDevices'
import {formatTime} from '../types'
import StatePanel from './StatePanel.vue'
defineProps<{open:boolean;result:ConfigCheck|null;pending:boolean;error:string}>()
const emit=defineEmits<{close:[];retry:[]}>()
const states={current:'文件与运行配置一致',restart_required:'文件已变化，需重启生效',invalid:'文件无法读取或配置无效',not_configured:'未配置本地连接器'}
</script>
<template><a-modal title="本地连接器配置核对" :open="open" :width="660" :footer="null" @cancel="emit('close')"><a-alert type="info" show-icon message="核对固定配置文件的访问权限、结构及运行绑定，不读取凭据内容、不测试设备连通性，也不应用配置。" class="section-gap"/><StatePanel :loading="pending" :error="error" @retry="emit('retry')"><template v-if="result"><a-alert :type="result.state==='current'?'success':result.state==='invalid'?'error':'warning'" show-icon :message="states[result.state]" class="section-gap"/><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="运行中的连接器">{{result.running_count}}</a-descriptions-item><a-descriptions-item label="文件中的连接器">{{result.state==='invalid'?'无法核对':result.file_count}}</a-descriptions-item><a-descriptions-item label="核对时间">{{formatTime(result.checked_at)}}</a-descriptions-item></a-descriptions><p class="page-description section-gap">配置来源为 SB_RESPONSE_CONNECTORS_FILE 指向的本机私有文件，权限应为 0600。配置文件与受信 CA 调整后需重启采集器；相同路径的 Bearer 文件支持原子轮换。核对结果不证明 CA 或凭据有效。</p></template></StatePanel><div class="filter-actions section-gap"><a-button :loading="pending" @click="emit('retry')">重新核对</a-button><a-button @click="emit('close')">关闭</a-button></div></a-modal></template>
