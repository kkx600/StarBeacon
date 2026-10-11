<script setup lang="ts">
import {computed,ref,watch} from 'vue'
import type {BusinessRecord} from '../models'
import {exportJson} from '../composables/useRecords'
const props=defineProps<{open:boolean;archives:BusinessRecord[]}>()
const emit=defineEmits<{close:[]}>()
const mode=ref('full_session')
const clientIP=ref('192.0.2.10'),serverIP=ref('198.51.100.20')
const clientPort=ref(40000),serverPort=ref(80)
const clientMAC=ref('02:00:00:00:00:01'),serverMAC=ref('02:00:00:00:00:02'),vlans=ref('')
const error=ref('')
const ids=computed(()=>props.archives.map(row=>row.id))
watch(()=>props.open,open=>{if(open){error.value='';mode.value='full_session'}})
function submit(){
  const mac=/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/
  const vlanValues=vlans.value.trim()?vlans.value.split(',').map(v=>v.trim()):[]
  if(!ids.value.length||ids.value.length>16){error.value='请选择 1–16 个已归档的同源切片';return}
  if(!clientIP.value.trim()||!serverIP.value.trim()||!clientPort.value||!serverPort.value||!mac.test(clientMAC.value.toLowerCase())||!mac.test(serverMAC.value.toLowerCase())){error.value='请完整填写双端 IP、端口和六字节 MAC';return}
  if(vlanValues.length>8||vlanValues.some(v=>!/^\d+$/.test(v)||Number(v)>4095)){error.value='VLAN 使用逗号分隔，最多八层，每层为 0–4095';return}
  exportJson('session-request-example',{example:true,archive_ids:ids.value,mode:mode.value,client_ip:clientIP.value.trim(),client_port:clientPort.value,server_ip:serverIP.value.trim(),server_port:serverPort.value,client_mac:clientMAC.value.toLowerCase(),server_mac:serverMAC.value.toLowerCase(),vlans:vlanValues.map(Number),notice:'合成目录与参数示例；没有读取实际原包或生成 PCAPNG'})
}
</script>
<template>
  <a-modal :open="open" title="会话导出" :width="820" :footer="null" @cancel="emit('close')">
    <a-alert show-icon type="info" message="原型仅展示选择参数，不生成通信证据。" description="实际导出须核验指定原包版本、权限与完整性；参数示例为 JSON，不是 PCAPNG。"/>
    <p class="session-source">已选 {{ids.length}} 个切片 · 最多 16 个 · 输入上限 256 MiB · 输出上限 64 MiB</p>
    <a-form layout="vertical" @finish="submit">
      <a-form-item label="导出模式"><a-radio-group v-model:value="mode"><a-radio value="full_session">完整 TCP 会话</a-radio><a-radio value="snapshot">通信快照</a-radio></a-radio-group></a-form-item>
      <p class="muted">{{mode==='full_session'?'握手、双向载荷或 FIN 确认存在缺口时拒绝导出，不自动改为快照。':'只复制实际匹配报文，文件保留快照标签和完整性缺口。'}}</p>
      <div class="session-grid">
        <a-form-item label="客户端 IP" required><a-input v-model:value="clientIP"/></a-form-item>
        <a-form-item label="客户端端口" required><a-input-number v-model:value="clientPort" :min="1" :max="65535"/></a-form-item>
        <a-form-item label="客户端 MAC" required><a-input v-model:value="clientMAC"/></a-form-item>
        <a-form-item label="服务端 IP" required><a-input v-model:value="serverIP"/></a-form-item>
        <a-form-item label="服务端端口" required><a-input-number v-model:value="serverPort" :min="1" :max="65535"/></a-form-item>
        <a-form-item label="服务端 MAC" required><a-input v-model:value="serverMAC"/></a-form-item>
      </div>
      <a-form-item label="VLAN 栈" extra="从外层到内层，逗号分隔；无 VLAN 时留空。"><a-input v-model:value="vlans" placeholder="例如 101,102"/></a-form-item>
      <a-alert v-if="error" show-icon type="error" :message="error"/>
      <p class="muted">不自动合并跨探针、注册代次、网卡、捕获运行或 NAT 流量，不补造握手与 TLS 明文。</p>
      <div class="session-actions"><a-button @click="emit('close')">关闭</a-button><a-button type="primary" html-type="submit" :disabled="!ids.length">导出参数示例</a-button></div>
    </a-form>
  </a-modal>
</template>
<style scoped>
.session-source{margin:12px 0;color:var(--muted);overflow-wrap:anywhere}.session-grid{display:grid;grid-template-columns:1.4fr .8fr 1.4fr;gap:0 12px}.session-grid :deep(.ant-input-number){width:100%}.session-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}@media(max-width:760px){.session-grid{grid-template-columns:1fr}}
</style>
