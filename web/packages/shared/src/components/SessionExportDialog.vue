<script setup lang="ts">
import {Modal as AModal,InputNumber as AInputNumber,Radio as ARadio} from 'ant-design-vue'
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {SessionExportError,type ApiClient} from '../api'
import {packetCapture,sessionReasons,type PacketRecord,type SessionExportRequest,type SessionExportReport} from '../packetArchives'
import {formatBytes} from '../utils/format'
const ARadioGroup=ARadio.Group
const props=defineProps<{api:ApiClient;archives:PacketRecord[];open:boolean}>()
const emit=defineEmits<{close:[]}>()
const form=reactive({mode:'full_session' as SessionExportRequest['mode'],client_ip:'',client_port:0,server_ip:'',server_port:0,client_mac:'',server_mac:'',vlans:''})
const pending=shallowRef(false),error=shallowRef(''),success=shallowRef(''),report=shallowRef<SessionExportReport|null>(null)
let controller:AbortController|undefined,url='',timer:ReturnType<typeof setTimeout>|undefined
const vlanIDs=computed(()=>form.vlans.trim()===''?[]:form.vlans.split(',').map(value=>/^\d{1,4}$/.test(value.trim())?Number(value.trim()):NaN))
const invalid=computed(()=>props.archives.length<1||props.archives.length>16||!form.client_ip.trim()||!form.server_ip.trim()||[form.client_port,form.server_port].some(v=>!Number.isInteger(v)||v<1||v>65535)||[form.client_mac,form.server_mac].some(v=>!/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/.test(v.trim().toLowerCase()))||vlanIDs.value.length>8||vlanIDs.value.some(v=>!Number.isInteger(v)||v<0||v>4095))
const source=computed(()=>props.archives.length?packetCapture(props.archives[0]):null)
const rawBytes=computed(()=>props.archives.reduce((sum,row)=>sum+(row.raw_bytes??row.manifest?.encoding.raw_bytes??0),0))
function revoke(){if(timer)clearTimeout(timer);if(url)URL.revokeObjectURL(url);url=''}
function cancel(){controller?.abort();pending.value=false;emit('close')}
watch(()=>props.open,open=>{if(open){Object.assign(form,{mode:'full_session',client_ip:'',client_port:0,server_ip:'',server_port:0,client_mac:'',server_mac:'',vlans:''});error.value='';success.value='';report.value=null}else{controller?.abort();pending.value=false}})
async function submit(){
 if(pending.value||invalid.value)return
 const input:SessionExportRequest={archive_ids:props.archives.map(row=>row.id),mode:form.mode,client_ip:form.client_ip.trim(),client_port:form.client_port,server_ip:form.server_ip.trim(),server_port:form.server_port,client_mac:form.client_mac.trim().toLowerCase(),server_mac:form.server_mac.trim().toLowerCase(),vlans:[...vlanIDs.value]}
 const requested=new AbortController();controller=requested;pending.value=true;error.value='';success.value='';report.value=null
 try{
  const blob=await props.api.downloadPacket('/packet-archives/session-export',requested.signal,input)
  if(requested.signal.aborted)return
  revoke();url=URL.createObjectURL(blob);const anchor=document.createElement('a');anchor.href=url;anchor.download=`session-${input.archive_ids[0]}-${input.mode}.pcapng`;document.body.append(anchor);anchor.click();anchor.remove();timer=setTimeout(revoke,1000)
  success.value=`${input.mode==='full_session'?'完整会话':'会话快照'}已通过 SHA-256 校验，下载已开始。文件包含源对象清单与逐包来源映射。`
 }catch(e){if(!requested.signal.aborted){error.value=e instanceof Error?e.message:'会话导出失败，请稍后重试';if(e instanceof SessionExportError)report.value=e.report}}
 finally{if(!requested.signal.aborted)pending.value=false}
}
onScopeDispose(()=>{controller?.abort();revoke()})
</script>
<template>
 <a-modal title="会话导出" :open="open" :width="820" :footer="null" :mask-closable="!pending" @cancel="cancel">
  <a-alert type="info" show-icon class="section-gap" message="完整会话需核实真实握手、双向字节连续性及 FIN 关闭确认。缺失时返回原因；快照只保存实际匹配报文。TLS 密文不会因此解密。"/>
  <p v-if="source" class="muted export-source">已选择 {{archives.length}} 个切片 · {{formatBytes(rawBytes)}} · {{source.sensor_id}} / {{source.interface}}。范围限于同一注册、捕获进程及配置；最多 256 MiB 输入、1 小时窗口与 64 MiB 输出。</p>
  <a-alert v-if="error" type="error" show-icon class="section-gap" :message="error"/>
  <div v-if="report" class="export-reasons"><strong>完整性核对结果</strong><ul><li v-for="reason in report.reasons" :key="reason">{{sessionReasons[reason]??'存在尚未确认的完整性约束'}}</li></ul><p>匹配 {{report.packets.toLocaleString('zh-CN')}} 包 · {{formatBytes(report.packet_bytes)}}。严格模式不会自动改为快照。</p></div>
  <a-alert v-if="success" type="success" show-icon class="section-gap" :message="success"/>
  <form class="export-form" @submit.prevent="submit">
   <a-form layout="vertical" :disabled="pending">
    <a-form-item label="导出模式"><a-radio-group v-model:value="form.mode" aria-label="会话导出模式"><a-radio value="full_session">完整会话</a-radio><a-radio value="snapshot">会话快照</a-radio></a-radio-group></a-form-item>
    <div class="export-grid"><a-form-item label="连接发起端 IP" required><a-input v-model:value="form.client_ip" aria-label="连接发起端 IP" :maxlength="45" placeholder="IPv4 或 IPv6"/></a-form-item><a-form-item label="连接发起端端口" required><a-input-number v-model:value="form.client_port" aria-label="连接发起端端口" :min="1" :max="65535" :precision="0"/></a-form-item><a-form-item label="连接发起端 MAC" required><a-input v-model:value="form.client_mac" aria-label="连接发起端 MAC" :maxlength="17" placeholder="00:00:00:00:00:00"/></a-form-item></div>
    <div class="export-grid"><a-form-item label="服务端 IP" required><a-input v-model:value="form.server_ip" aria-label="服务端 IP" :maxlength="45" placeholder="IPv4 或 IPv6"/></a-form-item><a-form-item label="服务端端口" required><a-input-number v-model:value="form.server_port" aria-label="服务端端口" :min="1" :max="65535" :precision="0"/></a-form-item><a-form-item label="服务端 MAC" required><a-input v-model:value="form.server_mac" aria-label="服务端 MAC" :maxlength="17" placeholder="00:00:00:00:00:00"/></a-form-item></div>
    <a-form-item label="VLAN 标识"><a-input v-model:value="form.vlans" aria-label="会话 VLAN 标识" :maxlength="39" placeholder="无 VLAN 时留空；多个标签按外到内用英文逗号分隔"/></a-form-item>
   </a-form>
   <div class="export-actions"><a-button @click="cancel">{{pending?'取消导出':'关闭'}}</a-button><a-button type="primary" html-type="submit" :loading="pending" :disabled="invalid||pending">验证并导出</a-button></div>
  </form>
 </a-modal>
</template>
<style scoped>.export-source{overflow-wrap:anywhere;font-size:12px;line-height:1.7}.export-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(110px,.65fr) minmax(0,1fr);gap:12px}.export-grid .ant-input-number{width:100%}.export-actions{display:flex;justify-content:flex-end;gap:8px}.export-reasons{padding:12px;border:1px solid var(--line);border-radius:6px;margin:12px 0}.export-reasons ul{margin:8px 0;padding-left:20px;line-height:1.7}.export-reasons p{font-size:12px;margin:8px 0 0}@media(max-width:760px){.export-grid{grid-template-columns:minmax(0,1fr)}.export-grid .ant-form-item{margin-bottom:8px}}</style>
