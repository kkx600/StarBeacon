<script setup lang="ts">
import {computed,nextTick,reactive,ref,watch} from 'vue'
import {message} from 'ant-design-vue'
import type {FormInstance} from 'ant-design-vue'
import type {CollectorAction,CollectorTask} from '../data/collector'
import {validateManagement,validateCapture,validateConnection,validateMaintenance} from '../data/collector'
import {useCollector} from '../composables/useCollector'
const props=defineProps<{open:boolean;action:CollectorAction;serviceId?:string}>()
const emit=defineEmits<{close:[];requested:[task:CollectorTask]}>()
const {state,device,request}=useCollector();const formRef=ref<FormInstance>();const errors=ref<string[]>([]);const checked=ref('')
const draft=reactive({...state.network,...state.capture,interfaces:[...state.capture.interfaces],...state.connection,...state.maintenance,syncMode:state.syncMode,syncMinutes:state.syncMinutes,autoApply:state.autoApply,key:'',source:'主控平台',packageId:state.ruleDesired,component:'Agent',targetVersion:state.agentDesired,window:'维护窗口内执行',reason:'',serviceId:'suricata',operation:'重启服务',confirm:false})
const titles:Record<CollectorAction,string>={network:'配置管理网络',capture:'编辑采集配置',connection:'配置平台接入',enroll:'使用注册密钥',certificate:'申请证书轮换','rule-sync':'同步规则','sync-settings':'配置规则同步',upgrade:'创建升级申请',rollback:'申请规则回滚',maintenance:'配置时间与存储',service:'服务维护',diagnostic:'生成诊断包'}
const title=computed(()=>titles[props.action])
const interfaceOptions=computed(()=>state.interfaces.filter(item=>item.role!=='系统').map(item=>({value:item.id,label:`${item.name} · ${item.role} · ${item.status}`,disabled:props.action==='capture'?(item.id===state.network.interface):(state.capture.interfaces.includes(item.id))})))
const canSubmit=computed(()=>checked.value===JSON.stringify(snapshot())&&draft.confirm&&(props.action!=='enroll'||draft.key.trim().length>=8))
watch(()=>[props.open,props.action,props.serviceId],async()=>{
  if(!props.open){draft.key='';checked.value='';return}
  Object.assign(draft,state.network,state.capture,{interfaces:[...state.capture.interfaces]},state.connection,state.maintenance,{syncMode:state.syncMode,syncMinutes:state.syncMinutes,autoApply:state.autoApply,key:'',source:'主控平台',packageId:props.action==='rollback'?state.ruleRollback:state.ruleDesired,component:'Agent',targetVersion:state.agentDesired,window:'维护窗口内执行',reason:'',serviceId:props.serviceId??'suricata',operation:'重启服务',confirm:false})
  errors.value=[];checked.value='';await nextTick();formRef.value?.clearValidate()
},{immediate:true})
function snapshot(){
  const keys:Record<CollectorAction,string[]>={network:['interface','method','ipv4','gateway','ipv6','gateway6','dns','mtu','rollbackSeconds'],capture:['interfaces','backend','homeNet','bpf','snaplen','threads','clusterBase','promisc','streamMiB','httpMiB','fileMiB'],connection:['host','port','serverName','caRef','clientRef','artifactUrl','heartbeat','batch','retrySeconds'],enroll:['host','port'],certificate:['clientRef'], 'rule-sync':['source','packageId'],'sync-settings':['syncMode','syncMinutes','autoApply'],upgrade:['source','component','targetVersion','window'],rollback:['packageId'],maintenance:['hostname','timezone','ntp','walGiB','pcapGiB','highWater','logDays'],service:['serviceId','operation'],diagnostic:['serviceId']}
  const values=draft as unknown as Record<string,unknown>
  return Object.fromEntries([...keys[props.action],'reason'].map(key=>[key,props.action==='network'&&draft.method==='DHCP'&&['ipv4','gateway'].includes(key)?'由 DHCP 获取':values[key]]))
}
const changes=computed(()=>Object.entries(snapshot()).map(([key,value])=>({key,label:({interface:'管理网卡',method:'IPv4 获取方式',ipv4:'IPv4 地址',gateway:'IPv4 网关',ipv6:'IPv6 地址',gateway6:'IPv6 网关',dns:'DNS 地址',mtu:'MTU',rollbackSeconds:'回滚确认窗口（秒）',interfaces:'镜像网卡',backend:'捕获后端',homeNet:'HOME_NET',bpf:'BPF',snaplen:'捕获长度（字节）',threads:'每接口线程',clusterBase:'cluster-id 起始值',promisc:'混杂模式',streamMiB:'流重组深度（MiB）',httpMiB:'HTTP 检查深度（MiB）',fileMiB:'文件深度（MiB）',host:'平台主机',port:'gRPC 端口',serverName:'TLS 服务名',caRef:'CA 引用',clientRef:'证书引用',artifactUrl:'制品地址',heartbeat:'心跳（秒）',batch:'批次（条）',retrySeconds:'起始重试（秒）',syncMode:'同步方式',syncMinutes:'核对周期（分钟）',autoApply:'验证后自动重载',source:'制品来源',packageId:'规则包',component:'升级组件',targetVersion:'目标版本',window:'执行窗口',hostname:'主机名',timezone:'时区',ntp:'NTP',walGiB:'WAL 配额（GiB）',pcapGiB:'PCAP 缓冲（GiB）',highWater:'高水位（%）',logDays:'日志留存（天）',serviceId:'服务',operation:'维护动作',reason:'操作原因'} as Record<string,string>)[key]??key,value:Array.isArray(value)?value.join('、'):typeof value==='boolean'?value?'开启':'关闭':String(value||'未配置')})).filter(item=>item.key!=='reason'))
async function check(){
  errors.value=[];checked.value=''
  try{await formRef.value?.validate()}catch{errors.value=['请填写必填字段并核对输入格式。'];return}
  if(props.action==='network')errors.value=validateManagement(draft,state.interfaces,state.capture.interfaces)
  else if(props.action==='capture')errors.value=validateCapture(draft,state.interfaces,state.network.interface)
  else if(props.action==='connection')errors.value=validateConnection(draft)
  else if(props.action==='maintenance')errors.value=validateMaintenance(draft)
  else if(props.action==='enroll'&&draft.key.trim().length<8)errors.value=['请提供至少 8 位的注册密钥；原型测试请使用合成密钥。']
  else if(['rule-sync','rollback'].includes(props.action)&&![state.ruleDesired,state.ruleRollback].includes(draft.packageId))errors.value=['请选择平台登记的示例规则包，不能输入任意下载地址。']
  else if(props.action==='sync-settings'&&(!Number.isInteger(draft.syncMinutes)||draft.syncMinutes<1||draft.syncMinutes>1440))errors.value=['规则版本核对周期应为 1–1440 分钟的整数。']
  else if(props.action==='upgrade'&&!draft.targetVersion.trim())errors.value=['目标版本不能为空。']
  if(!draft.reason.trim())errors.value.push('请填写操作原因。')
  if(!errors.value.length)checked.value=JSON.stringify(snapshot())
}
async function submit(){
  if(!canSubmit.value){message.warning('请先检查当前配置，并确认变更范围。');return}
  // 注册密钥只用于本次输入校验；任务、日志与设备配置不保存该值。
  const target=props.action==='network'?draft.interface:props.action==='capture'?draft.interfaces.join(','):props.action==='rule-sync'||props.action==='rollback'?draft.packageId:props.action==='upgrade'?`${draft.component} / ${draft.targetVersion}`:device.id
  const summary=`${props.action==='network'?`网络变更确认窗口 ${draft.rollbackSeconds} 秒；实际应用与自动回滚尚未执行。 `:''}${changes.value.map(item=>`${item.label}：${item.value}`).join('；')}。原因：${draft.reason.trim()}。仅创建本地申请，等待设备能力、授权和执行回执。`
  const task=request(props.action,target,summary);draft.key='';emit('requested',task)
}
</script>
<template>
  <a-modal :open="open" :title="title" :width="820" destroy-on-close :footer="null" class="collector-form-modal" @cancel="emit('close')">
    <div class="collector-form-body">
      <a-alert type="info" show-icon class="modal-notice" message="检查输入格式后创建配置申请。真实网络测试、制品校验与设备执行需要采集器服务返回回执；原型仅保存本地申请。"/>
      <a-form ref="formRef" :model="draft" layout="vertical" class="operation-form">
        <div class="form-grid">
          <template v-if="action==='network'">
            <a-form-item label="管理网卡" name="interface" :rules="[{required:true,message:'请选择管理网卡'}]"><a-select v-model:value="draft.interface" :options="interfaceOptions"/></a-form-item>
            <a-form-item label="IPv4 获取方式" name="method"><a-select v-model:value="draft.method" :options="['静态地址','DHCP'].map(value=>({value,label:value}))"/></a-form-item>
            <a-form-item label="IPv4 地址 / 前缀" name="ipv4"><a-input v-model:value="draft.ipv4" :disabled="draft.method==='DHCP'" placeholder="10.20.0.8/24"/></a-form-item><a-form-item label="IPv4 网关" name="gateway"><a-input v-model:value="draft.gateway" :disabled="draft.method==='DHCP'" placeholder="10.20.0.1"/></a-form-item>
            <a-form-item label="IPv6 地址 / 前缀（可选）" name="ipv6"><a-input v-model:value="draft.ipv6" placeholder="2001:db8:20::8/64"/></a-form-item><a-form-item label="IPv6 网关（可选）" name="gateway6"><a-input v-model:value="draft.gateway6" placeholder="2001:db8:20::1"/></a-form-item>
            <a-form-item label="DNS 地址" name="dns"><a-input v-model:value="draft.dns" placeholder="1–3 个地址，逗号分隔"/></a-form-item><a-form-item label="MTU（字节）" name="mtu"><a-input-number v-model:value="draft.mtu" :min="576" :max="9000" :precision="0"/></a-form-item>
            <a-form-item label="回滚确认窗口（秒）" name="rollbackSeconds"><a-input-number v-model:value="draft.rollbackSeconds" :min="60" :max="300" :precision="0"/><small class="field-hint">实际变更后需从新地址确认可达，超时自动恢复旧配置。原型不启动真实倒计时。</small></a-form-item><p class="field-hint collector-form-explanation">改变管理地址可能断开当前会话。系统需先保存旧配置、验证网关与路由，再应用并等待确认。DHCP 地址由设备实测回读。</p>
          </template>
          <template v-else-if="action==='capture'">
            <a-form-item label="镜像采集网卡" name="interfaces" class="form-span-2" :rules="[{required:true,type:'array',message:'请选择镜像网卡'}]"><a-select v-model:value="draft.interfaces" mode="multiple" :options="interfaceOptions" placeholder="可选择多张镜像网卡"/><small class="field-hint">管理口与回环接口不可选。每张网卡分配独立 cluster-id，流量计量保留接口来源。</small></a-form-item>
            <a-form-item label="捕获后端" name="backend"><a-select v-model:value="draft.backend" :options="[{value:'AF_PACKET',label:'AF_PACKET（本机示例能力）'}]"/></a-form-item><a-form-item label="混杂模式" name="promisc"><a-switch v-model:checked="draft.promisc" checked-children="开启" un-checked-children="关闭"/></a-form-item>
            <a-form-item label="HOME_NET" class="form-span-2" name="homeNet"><a-input v-model:value="draft.homeNet" placeholder="IPv4／IPv6 CIDR，逗号分隔"/></a-form-item><a-form-item label="BPF 过滤（可选）" class="form-span-2" name="bpf"><a-input v-model:value="draft.bpf" placeholder="默认不额外过滤"/><small class="field-hint">BPF 需由捕获后端编译验证；过滤可能排除握手和证据。当前表单不执行 BPF 编译。</small></a-form-item>
            <a-form-item label="捕获长度上限（字节）" name="snaplen"><a-input-number v-model:value="draft.snaplen" :min="64" :max="262144" :precision="0"/><small class="field-hint">需覆盖 MTU 与封装。原包捕获和 Suricata 重组深度分别设置。</small></a-form-item><a-form-item label="每接口线程数" name="threads"><a-input-number v-model:value="draft.threads" :min="1" :max="32" :precision="0"/></a-form-item>
            <a-form-item label="cluster-id 起始值" name="clusterBase"><a-input-number v-model:value="draft.clusterBase" :min="1" :max="65535" :precision="0"/></a-form-item><a-form-item label="TCP 重组深度（MiB）" name="streamMiB"><a-input-number v-model:value="draft.streamMiB" :min="1" :max="1024" :precision="0"/></a-form-item><a-form-item label="HTTP 检查深度（MiB）" name="httpMiB"><a-input-number v-model:value="draft.httpMiB" :min="1" :max="1024" :precision="0"/></a-form-item><a-form-item label="文件提取深度（MiB）" name="fileMiB"><a-input-number v-model:value="draft.fileMiB" :min="1" :max="1024" :precision="0"/></a-form-item>
            <p class="field-hint form-span-2">实际能力还需检查驱动、GRO／LRO、RSS、NUMA 与引擎内存。TLS 密文、检测深度和捕获缺口不会因增大捕获长度而自动消失。</p>
          </template>
          <template v-else-if="action==='connection'">
            <a-form-item label="主控平台主机" name="host" :rules="[{required:true,message:'请输入平台主机'}]"><a-input v-model:value="draft.host" placeholder="platform.example.test"/></a-form-item><a-form-item label="gRPC 端口" name="port"><a-input-number v-model:value="draft.port" :min="1" :max="65535" :precision="0"/></a-form-item>
            <a-form-item label="TLS 服务名" name="serverName"><a-input v-model:value="draft.serverName"/></a-form-item><a-form-item label="受信 CA 引用" name="caRef"><a-input v-model:value="draft.caRef"/></a-form-item><a-form-item label="本机证书引用" name="clientRef"><a-input v-model:value="draft.clientRef"/><small class="field-hint">仅使用本机凭据存储引用，不输入或导出私钥。</small></a-form-item><a-form-item label="制品 HTTPS 地址" name="artifactUrl"><a-input v-model:value="draft.artifactUrl"/></a-form-item>
            <a-form-item label="心跳周期（秒）" name="heartbeat"><a-input-number v-model:value="draft.heartbeat" :min="15" :max="300" :precision="0"/></a-form-item><a-form-item label="事件批次（条）" name="batch"><a-input-number v-model:value="draft.batch" :min="1" :max="4096" :precision="0"/></a-form-item><a-form-item label="重试起始间隔（秒）" name="retrySeconds"><a-input-number v-model:value="draft.retrySeconds" :min="1" :max="60" :precision="0"/></a-form-item><p class="field-hint collector-form-explanation">通信强制使用 mTLS。设备绑定由主平台核验；修改地址不改变租户身份。重试采用有界退避，事件与控制通道分离。</p>
          </template>
          <template v-else-if="action==='enroll'">
            <a-form-item label="一次性注册密钥" name="key" class="form-span-2" :rules="[{required:true,message:'请填写注册密钥'}]"><a-input-password v-model:value="draft.key" autocomplete="off" placeholder="原型测试请使用合成密钥，例如 demo-registration-only" :visibility-toggle="false"/><small class="field-hint">仅写，不回显，不保存到任务和日志。已注册设备的重注册需主平台授权。</small></a-form-item><p class="field-hint form-span-2">平台核验密钥有效期、单次使用和设备绑定后，才可签发设备证书。当前输入不会进行真实注册。</p>
          </template>
          <template v-else-if="action==='certificate'"><a-form-item label="当前本机证书引用" class="form-span-2"><a-input :value="state.connection.clientRef" disabled/></a-form-item><p class="field-hint form-span-2">新私钥由设备生成，平台审批后签发证书；新连接验证成功前保留旧证书。此申请不生成私钥、不变更真实权限。</p></template>
          <template v-else-if="action==='sync-settings'"><a-form-item label="规则同步方式" name="syncMode"><a-select v-model:value="draft.syncMode" :options="['平台推送','定时拉取','手动同步'].map(value=>({value,label:value}))"/></a-form-item><a-form-item label="版本核对周期（分钟）" name="syncMinutes"><a-input-number v-model:value="draft.syncMinutes" :min="1" :max="1440" :precision="0"/></a-form-item><a-form-item label="验证通过后自动重载" name="autoApply"><a-switch v-model:checked="draft.autoApply" checked-children="开启" un-checked-children="关闭"/></a-form-item><p class="field-hint collector-form-explanation">自动重载仅接受授权签名制品，配置测试和资源检查通过后执行；重载结果仍需回读。断网保持现行规则，恢复后按最新发布代次对账。</p></template>
          <template v-else-if="action==='rule-sync'||action==='upgrade'||action==='rollback'">
            <a-form-item v-if="action!=='rollback'" label="制品来源" name="source"><a-select v-model:value="draft.source" :options="['主控平台','签名离线包'].map(value=>({value,label:value}))"/></a-form-item>
            <template v-if="action==='upgrade'"><a-form-item label="升级组件" name="component"><a-select v-model:value="draft.component" :options="['Agent','Suricata 引擎','采集器系统镜像'].map(value=>({value,label:value}))" @change="draft.targetVersion=draft.component==='Agent'?state.agentDesired:draft.component==='Suricata 引擎'?'Suricata 8.0.7':'系统镜像示例目标构建'"/></a-form-item><a-form-item label="目标版本" name="targetVersion"><a-input v-model:value="draft.targetVersion"/></a-form-item><a-form-item label="执行窗口" name="window"><a-select v-model:value="draft.window" :options="['维护窗口内执行','审批后执行'].map(value=>({value,label:value}))"/></a-form-item></template>
            <a-form-item v-else label="目标规则包" name="packageId"><a-select v-model:value="draft.packageId" :options="(action==='rollback'?[state.ruleRollback]:[state.ruleDesired]).map(value=>({value,label:value}))"/></a-form-item>
            <a-form-item v-if="draft.source==='签名离线包'&&action!=='rollback'" label="离线制品文件" class="form-span-2"><a-input value="sb-signed-bundle-demo.tar.zst" disabled/><small class="field-hint">当前仅展示合成文件名，不读取或上传制品。生产导入需校验签名、摘要、版本兼容及绑定范围。</small></a-form-item>
            <p class="field-hint form-span-2">规则包先下载并验证签名，运行 Suricata 配置测试后重载，再回读实际版本。系统升级按组件检查兼容性并保护 WAL、PCAP 与撤销 journal；操作系统镜像需单独维护窗口和恢复分区。回滚创建独立任务，不覆盖历史回执。</p>
          </template>
          <template v-else-if="action==='maintenance'">
            <a-form-item label="主机名" name="hostname"><a-input v-model:value="draft.hostname"/></a-form-item><a-form-item label="显示时区" name="timezone"><a-select v-model:value="draft.timezone" :options="['Asia/Shanghai','UTC'].map(value=>({value,label:value}))"/></a-form-item><a-form-item label="NTP 服务器" class="form-span-2" name="ntp"><a-input v-model:value="draft.ntp" placeholder="1–3 个主机名或地址，逗号分隔"/></a-form-item>
            <a-form-item label="事件 WAL 配额（GiB）" name="walGiB"><a-input-number v-model:value="draft.walGiB" :min="1" :max="100" :precision="0"/></a-form-item><a-form-item label="本地 PCAP 缓冲配额（GiB）" name="pcapGiB"><a-input-number v-model:value="draft.pcapGiB" :min="10" :max="250" :precision="0"/></a-form-item><a-form-item label="磁盘高水位（%）" name="highWater"><a-input-number v-model:value="draft.highWater" :min="50" :max="95" :precision="0"/></a-form-item><a-form-item label="操作日志留存（天）" name="logDays"><a-input-number v-model:value="draft.logDays" :min="1" :max="3650" :precision="0"/><small class="field-hint">默认 180 天；缩短期限需评估影响并保留审计。</small></a-form-item><p class="field-hint form-span-2">本机示例可分配缓冲为 300 GiB。配置只约束本地空间；全量 PCAP、告警及平台业务数据默认归档保留 180 天，不因本地缓冲回收而缩短。</p>
          </template>
          <template v-else><a-form-item label="维护服务" name="serviceId"><a-select v-model:value="draft.serviceId" :options="state.services.filter(item=>item.id!=='runner').map(item=>({value:item.id,label:item.name}))"/></a-form-item><a-form-item v-if="action==='service'" label="维护动作" name="operation"><a-select v-model:value="draft.operation" :options="['重启服务','进入维护模式','退出维护模式'].map(value=>({value,label:value}))"/></a-form-item><p class="field-hint form-span-2">{{action==='diagnostic'?'诊断包默认仅包含脱敏配置、资源指标、版本和错误摘要，排除凭据、Cookie 与通信载荷。':'重启可能造成采集或上报间隙。维护模式不暂停已有响应动作的到期撤销职责，也不清空持久缓冲。'}}</p></template>
          <a-form-item label="操作原因" name="reason" class="form-span-2" :rules="[{required:true,message:'请填写操作原因'}]"><a-textarea v-model:value="draft.reason" :rows="2" placeholder="说明配置目的、影响范围与维护依据"/></a-form-item>
        </div>
      </a-form>
      <a-alert v-if="errors.length" type="error" show-icon message="配置检查未通过" class="modal-notice"><template #description><ul class="collector-errors"><li v-for="error in errors" :key="error">{{error}}</li></ul></template></a-alert>
      <template v-if="checked&&checked===JSON.stringify(snapshot())"><a-alert type="info" show-icon message="输入格式检查通过。设备能力、实际连通、制品验证和执行结果仍需回执。" class="modal-notice"/><h3 class="collector-detail-heading">申请内容</h3><a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small"><a-descriptions-item v-for="change in changes" :key="change.key" :label="change.label">{{change.value}}</a-descriptions-item></a-descriptions></template>
      <a-checkbox v-model:checked="draft.confirm" class="collector-confirm">已核对设备、配置范围与业务影响；提交后仍需等待执行和回读。</a-checkbox>
    </div>
    <div class="collector-modal-footer"><span class="muted">申请保存在当前原型会话中</span><a-space><a-button @click="emit('close')">取消</a-button><a-button @click="check">检查配置</a-button><a-button type="primary" :disabled="!canSubmit" @click="submit">创建申请</a-button></a-space></div>
  </a-modal>
</template>
