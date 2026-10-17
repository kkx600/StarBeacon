<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import {computed,onScopeDispose,shallowRef,watch} from 'vue'
import {Modal as AModal} from 'ant-design-vue'
import type {CaptureConfig,CaptureSettings,NetworkInterface,Sensor} from '@starbeacon/shared/types.ts'
import CaptureForm from '@starbeacon/shared/components/CaptureForm.vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
const message=useFeedback()
const props=defineProps<{sensor:Sensor|null}>()
const emit=defineEmits<{close:[];submitted:[]}>()
const capture=shallowRef<CaptureConfig|null>(null),interfaces=shallowRef<NetworkInterface[]>([])
const loading=shallowRef(false),saving=shallowRef(false),error=shallowRef(''),saveError=shallowRef('')
let controller:AbortController|undefined,key='',stamp='',disposed=false
const title=computed(()=>props.sensor?`采集配置 · ${props.sensor.name}`:'采集配置')
async function load(){
  const target=props.sensor
  controller?.abort();capture.value=null;interfaces.value=[];error.value='';saveError.value='';key='';stamp=''
  if(!target||disposed)return
  if(session.current.value?.role!=='admin'){error.value='当前账号没有采集配置权限';return}
  const current=new AbortController();controller=current;loading.value=true
  try{
    const data=await readSensorDirectory(session.api,current.signal)
    if(current.signal.aborted)return
    const row=data.find(i=>i.id===target.id&&i.registration_id===target.registration_id)
    const value=row?.health.capture
    const seen=Date.parse(row?.last_seen??''),network=row?.health.network_interfaces
    if(!row?.active||row.status!=='online'||!Number.isFinite(seen)||Date.now()-seen>35000||seen-Date.now()>60000||!row.health.task_capabilities?.includes('capture.configure')||!value?.managed||!Number.isSafeInteger(value.revision)||(value.revision??-1)<0||!value.settings_sha256?.match(/^[a-f0-9]{64}$/)||!Array.isArray(value.interfaces)||!value.interfaces.every(i=>typeof i==='string')||!Array.isArray(network)||network.some(i=>!i||typeof i.name!=='string'||typeof i.mac!=='string'||typeof i.up!=='boolean'||typeof i.loopback!=='boolean')||value.status==='pending'||value.status==='starting')throw new Error('探针未就绪或采集配置尚未完整观测，请刷新后核对。')
    capture.value=value;interfaces.value=network
  }catch(e){if(!current.signal.aborted)error.value=e instanceof Error?e.message:'无法读取探针采集配置'}
  finally{if(!current.signal.aborted)loading.value=false}
}
async function submit(settings:CaptureSettings){
  if(!props.sensor||!capture.value||saving.value||disposed||session.current.value?.role!=='admin')return
  const body={kind:'capture.configure',capture_configuration:{expected_revision:capture.value.revision,expected_config_sha256:capture.value.config_sha256??'',expected_settings_sha256:capture.value.settings_sha256,settings}}
  const fingerprint=JSON.stringify(body)
  if(stamp!==fingerprint){stamp=fingerprint;key=crypto.randomUUID()}
  const current=new AbortController();controller=current;saving.value=true;saveError.value=''
  try{
    await session.api.request(`/sensors/${encodeURIComponent(props.sensor.id)}/tasks`,{method:'POST',headers:{'Idempotency-Key':key},body,signal:current.signal})
    if(current.signal.aborted)return
    key='';stamp='';message.success('采集配置已受理，请在任务记录中核对设备回执');emit('submitted')
  }catch(e){if(!current.signal.aborted)saveError.value=e instanceof Error?e.message:'采集配置任务提交失败'}
  finally{if(!current.signal.aborted)saving.value=false}
}
watch(()=>`${props.sensor?.id??''}/${props.sensor?.registration_id??''}`,()=>{loading.value=false;saving.value=false;void load()},{immediate:true})
onScopeDispose(()=>{disposed=true;controller?.abort()})
</script>
<template>
  <a-modal :title="title" :open="sensor!==null" :footer="null" :width="820" :closable="!saving" :mask-closable="!saving" :keyboard="!saving" @cancel="emit('close')">
    <StatePanel :loading="loading" :error="error" :empty="false" @retry="load">
      <a-alert v-if="saveError" class="section-gap" type="error" show-icon :message="saveError" />
      <CaptureForm v-if="capture" :interfaces="interfaces" :capture="capture" :saving="saving" scope="platform" @save="submit" />
    </StatePanel>
  </a-modal>
</template>
