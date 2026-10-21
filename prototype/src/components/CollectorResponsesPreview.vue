<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import type {PreviewState} from '../models'
import StatePanel from './StatePanel.vue'
import ResponseConnectors from '../../../web/packages/shared/src/components/ResponseConnectors.vue'
import ResponseConfigCheckDialog from '../../../web/packages/shared/src/components/ResponseConfigCheckDialog.vue'
import type {ResponseConnector} from '../../../web/packages/shared/src/response'
import type {ConfigCheck} from '../../../web/packages/shared/src/responseDevices'
const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>()
const at=new Date().toISOString(),rows:ResponseConnector[]=[{connector_id:'connector_hq',device_id:'device_hq',version:'protocol-fixture/1',status:'ready',max_ttl_seconds:3600,observed_at:at,config_sha256:'a'.repeat(64)},{connector_id:'connector_branch',device_id:'device_branch',version:'protocol-fixture/1',status:'unavailable',max_ttl_seconds:300,observed_at:at,config_sha256:'b'.repeat(64)}]
const items=computed(()=>props.state==='empty'?[]:rows),checkOpen=shallowRef(false),result:ConfigCheck={schema_version:'response.config-check.v1',state:'current',running_count:2,file_count:2,checked_at:at}
watch(()=>props.state,value=>{checkOpen.value=value==='action'},{immediate:true})
function close(){checkOpen.value=false;if(['detail','action'].includes(props.state))emit('state','data')}
</script>
<template><StatePanel v-if="['loading','error'].includes(state)" :state="state as 'loading'|'error'" :description="state==='error'?'设备目录未能读取，当前认证与配置状态未知。请刷新核对。':undefined" @action="emit('state','data')"/><template v-else><a-alert type="info" show-icon message="以下为合成目录，与工程端使用相同的设备列表、详情及本地配置核对组件，不读取本机文件或连接设备。" class="section-gap"/><div class="configuration-check"><span class="page-description">核对本机文件与运行配置是否一致。</span><a-button @click="checkOpen=true">核对本地配置</a-button></div><ResponseConnectors :items="items" :detailID="state==='detail'?'connector_hq':undefined" @close="close"/></template><ResponseConfigCheckDialog :open="checkOpen" :result="result" :pending="false" error="" @retry="checkOpen=true" @close="close"/></template>
<style scoped>.configuration-check{display:flex;justify-content:flex-end;align-items:center;flex-wrap:wrap;gap:var(--related-gap);margin-bottom:var(--section-gap)}.section-gap{margin-bottom:var(--section-gap)}</style>
