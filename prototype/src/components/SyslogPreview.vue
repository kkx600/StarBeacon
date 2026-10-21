<script setup lang="ts">
import {computed,reactive} from 'vue'
import {emptySourceQuery} from '../../../web/packages/shared/src/syslog'
import SyslogSourceFilters from '../../../web/packages/shared/src/components/SyslogSourceFilters.vue'
import SyslogSources from '../../../web/packages/shared/src/components/SyslogSources.vue'
import SyslogLogs from '../../../web/packages/shared/src/components/SyslogLogs.vue'
import type {PreviewState} from '../models'
import {syslogSource,syslogLog} from '../data/syslog'
import StatePanel from './StatePanel.vue'
const props=defineProps<{state:PreviewState;logs?:boolean;local?:boolean}>(),emit=defineEmits<{state:[state:PreviewState]}>()
const filters=reactive(emptySourceQuery())
const items=computed(()=>props.state==='empty'?[]:[syslogSource()])
function change(value:string){if(['data','empty','loading','error','detail','action'].includes(value))emit('state',value as PreviewState)}
</script>
<template><a-alert type="info" show-icon message="以下为合成日志，与工程端使用相同的来源列表、检索、详情和原文字节组件，不连接设备或读取生产数据。" class="section-gap"/><SyslogLogs v-if="logs" :preview="[syslogLog]" :state="state==='action'?'detail':state" @state="change"/><template v-else><header v-if="!local" class="page-header"><div><h1>Syslog 接收</h1><p class="page-description">核对采集器的固定日志来源、接收状态与持久缓冲，不以日志正文声明设备或租户身份。</p></div><a-button @click="emit('state','data')">刷新来源</a-button></header><SyslogSourceFilters v-if="!local" :model="filters" :pending="state==='loading'" @search="emit('state','data')" @reset="Object.assign(filters,emptySourceQuery());emit('state','data')"/><a-alert v-if="!local" type="info" show-icon message="TLS 来源校验客户端证书与指纹；TCP、UDP 来源使用明确授权的网段限制。来源配置由采集器私有文件管理，配置内容与监听地址不通过心跳公开。" class="section-gap"/><section class="panel"><div class="panel-header"><h2>日志来源</h2><span>{{state==='empty'?0:1}} 项</span></div><StatePanel v-if="['loading','error','empty'].includes(state)" :state="state as 'loading'|'error'|'empty'" description="当前条件下没有 Syslog 来源。请调整筛选，或配置采集器来源文件后核对心跳。" @action="emit('state','data')"/><SyslogSources v-else :items="items" :local="local" :detailID="['detail','action'].includes(state)?'firewall_syslog':undefined" @close="['detail','action'].includes(state)&&emit('state','data')"/></section></template></template>

<style scoped>.panel-header{display:flex;align-items:center;justify-content:space-between;gap:var(--field-gap);padding:var(--section-gap) var(--panel-inset)}.panel-header h2{margin:0;font-size:16px}</style>
