<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import { computed,defineAsyncComponent,shallowRef } from 'vue'
import {useRoute,useRouter} from 'vue-router'
import ProtocolCapabilitiesDialog from '@starbeacon/shared/components/ProtocolCapabilitiesDialog.vue'
import DetectionQualityDialog from '@starbeacon/shared/components/DetectionQualityDialog.vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import HealthSummary from './HealthSummary.vue'
import CollectorInterfacePanel from './CollectorInterfacePanel.vue'
import CollectorSyslogPanel from './CollectorSyslogPanel.vue'
import CollectorIdentity from './CollectorIdentity.vue'
import ResponseConnectors from '@starbeacon/shared/components/ResponseConnectors.vue'
import ResponseConfiguration from './ResponseConfiguration.vue'
import CaptureForm from '@starbeacon/shared/components/CaptureForm.vue'
import AsyncWorkspaceState from '@starbeacon/shared/components/AsyncWorkspaceState.vue'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import { session } from '../../session'
import {collectorScreens,collectorScreen,collectorWorkspaces} from '../../navigation'
import { useCollector } from './useCollector'
import {useCollectorDiagnostics} from './useCollectorDiagnostics'
import type {CaptureSettings} from '@starbeacon/shared/types.ts'
import {captureErrors} from '@starbeacon/shared/types.ts'
const message=useFeedback()
const ReplayWorkspace=defineAsyncComponent({loader:()=>import('@starbeacon/shared/components/ReplayWorkspace.vue'),loadingComponent:AsyncWorkspaceState,errorComponent:AsyncWorkspaceState,delay:150,timeout:30000})
const PacketArchiveWorkspace=defineAsyncComponent({loader:()=>import('@starbeacon/shared/components/PacketArchiveWorkspace.vue'),loadingComponent:AsyncWorkspaceState,errorComponent:AsyncWorkspaceState,delay:150,timeout:30000})
const route=useRoute(),router=useRouter()
const mountedPath=route.path,canonicalAtMount=typeof route.meta.workspaceView==='string'
const {view,change:legacyChange}=useWorkspaceView(collectorScreens.map(screen=>screen.view),'interfaces')
const views=collectorScreens.map(screen=>({key:screen.view,label:screen.title}))
const screen=computed(()=>collectorScreen(view.value)!)
const workspaceTitle=computed(()=>collectorWorkspaces.find(workspace=>workspace.id===route.meta.navWorkspace)?.title??'采集器管理')
function change(key:string){
  if(saving.value)return
  const target=collectorScreen(key)
  if(!target)return
  if(typeof route.meta.workspaceView!=='string')return legacyChange(key)
  const {view:ignoredView,task:ignoredTask,...query}=route.query
  return router.push({path:target.path,query,hash:route.hash})
}
const administrator=computed(()=>session.current?.value?.role==='admin')
const currentPath=computed(()=>!canonicalAtMount||route.path===mountedPath)
const protocolsOpen=shallowRef(false)
const qualityOpen=shallowRef(false)
const observed=computed(()=>['overview','interfaces','capture','responses','syslog'].includes(view.value))
const {health,interfaces,capture,pending,saving,error,refresh,save}=useCollector({resources:()=>{
  if(!administrator.value||!currentPath.value)return []
  const selected:('health'|'interfaces'|'capture')[]=[]
  if(['overview','responses','syslog'].includes(view.value))selected.push('health')
  if(['interfaces','capture'].includes(view.value))selected.push('interfaces')
  if(view.value==='capture')selected.push('capture')
  return selected
}})
const {health:diagnosticHealth,capture:diagnosticCapture,pending:diagnosticPending,error:diagnosticError,refresh:refreshDiagnostics}=useCollectorDiagnostics({enabled:()=>administrator.value&&currentPath.value,open:()=>protocolsOpen.value||qualityOpen.value})
async function submit(settings:CaptureSettings){try{if(await save(settings)){const value=capture.value;if(value.status==='running')message.success('采集配置已生效');else if(value.status==='stopped')message.success('采集已停止');else if(value.error_code)message.warning(captureErrors[value.error_code]??'配置已保存，实际执行状态需要核对');else message.success('采集目标保存成功，等待应用')}}catch(e){message.error(e instanceof Error?e.message:'保存失败')}}
</script>
<template>
  <template v-if="administrator&&currentPath">
  <header class="page-header"><div><h1>{{screen.title}}</h1><p class="page-description">{{screen.description}}</p></div><div class="filter-actions"><a-button :disabled="saving" @click="qualityOpen=true">检测质量</a-button><a-button :disabled="saving" @click="protocolsOpen=true">协议能力</a-button><a-button v-if="observed" :loading="pending" :disabled="saving" @click="refresh">刷新</a-button></div></header>
  <WorkspaceTabs :active="view" :items="views" :label="workspaceTitle+'功能'" @change="change" />
  <StatePanel v-if="observed" :loading="pending" :error="error" :empty="view==='overview'&&!health&&!pending&&!error" description="尚未取得本机运行状态。" @retry="refresh">
    <template v-if="view==='overview'"><HealthSummary v-if="health" :health="health" /></template>
    <CollectorInterfacePanel v-else-if="view==='interfaces'" :interfaces="interfaces" />
    <CollectorSyslogPanel v-else-if="view==='syslog'" :health="health" />
    <template v-else-if="view==='responses'"><ResponseConfiguration/><ResponseConnectors :items="health?.response_connectors??[]"/></template>
    <section v-else class="panel"><div class="panel-header"><h2>采集配置</h2></div><div class="panel-body"><CaptureForm :interfaces="interfaces" :capture="capture" :saving="saving" @save="submit" /></div></section>
  </StatePanel>
  <CollectorIdentity v-else-if="view==='identity'" />
  <PacketArchiveWorkspace v-else-if="view==='archives'" :api="session.api" local/>
  <ReplayWorkspace v-else :api="session.api" :principal="session.current.value" local @tasks="change('tasks')" :view="view==='tasks'?'tasks':'samples'" />
  <ProtocolCapabilitiesDialog :open="protocolsOpen" :report="diagnosticHealth?.protocol_capabilities" :capture="diagnosticCapture" :error="diagnosticError" refreshable :loading="diagnosticPending" @refresh="refreshDiagnostics" @close="protocolsOpen=false" />
  <DetectionQualityDialog :open="qualityOpen" :capture="diagnosticCapture" :error="diagnosticError" refreshable :loading="diagnosticPending" @refresh="refreshDiagnostics" @close="qualityOpen=false" />
  </template>
  <StatePanel v-else-if="!administrator" error="当前账号没有采集器本地管理权限。请使用具有管理权限的账号登录。" />
</template>
