<script setup lang="ts">
import {computed,reactive,shallowRef,watch} from 'vue'
import {Modal,Select,Checkbox,Switch,InputNumber} from 'ant-design-vue'
import {channelNames,severityOptions,streamOptions,type LogStream,type Channel,type ChannelChange,type ChannelKind} from './notifications'
const props=defineProps<{record:Channel|null;pending:boolean;error:string;development:boolean}>()
const emit=defineEmits<{save:[change:ChannelChange];close:[]}>()
const updateConnection=shallowRef(!props.record),formError=shallowRef('')
const id=props.record?.id??'channel_'+crypto.randomUUID().replaceAll('-','')
const model=reactive({streams:[...(props.record?.streams??['alerts'])] as LogStream[],name:props.record?.name??'',kind:props.record?.kind??'webhook' as ChannelKind,enabled:props.record?.enabled??true,severities:[...(props.record?.severities??['high','medium'])],mutedUntil:props.record?.muted_until??'',endpoint:'',secret:'',token:'',smtpHost:'',smtpPort:587,smtpUser:'',smtpPassword:'',from:'',recipients:'',implicitTLS:false})
const options=computed(()=>Object.entries(channelNames).filter(([key])=>props.development||key!=='syslog_tcp').map(([value,label])=>({value,label})))
const subscriptions=computed(()=>streamOptions.filter(item=>model.kind.startsWith('syslog_')||['alerts','quality'].includes(item.value)))
watch(()=>model.kind,()=>{model.endpoint='';model.secret='';model.token='';model.smtpHost='';model.smtpPort=587;model.smtpUser='';model.smtpPassword='';model.from='';model.recipients='';model.implicitTLS=false;if(!model.kind.startsWith('syslog_')){model.streams=model.streams.filter(item=>['alerts','quality'].includes(item));if(!model.streams.length)model.streams=['alerts']}})
function save(){
  if(props.pending)return
  formError.value=''
  if(!model.name.trim()||model.streams.includes('alerts')&&!model.severities.length){formError.value='请填写渠道名称并选择告警级别。';return}
  if(!model.streams.length){formError.value='请选择订阅内容。';return}
  let mutedUntil:string|null=null
  if(model.mutedUntil){const date=new Date(model.mutedUntil);if(Number.isNaN(date.getTime())){formError.value='静默截止时间无效。';return};mutedUntil=date.toISOString()}
  const change:ChannelChange={id,expected_revision:props.record?.revision??0,name:model.name.trim(),kind:model.kind,enabled:model.enabled,severities:model.streams.includes('alerts')?[...model.severities]:[],streams:[...model.streams],muted_until:mutedUntil}
  if(updateConnection.value){
    const recipients=model.recipients.split(/[\s,;；，]+/).filter(Boolean)
    if(model.kind==='email'&&(!model.smtpHost.trim()||!model.from.trim()||!recipients.length)){formError.value='请填写 SMTP 主机、发件地址和接收人。';return}
    if(model.kind!=='email'&&!model.endpoint.trim()){formError.value='请填写渠道目标地址。';return}
    change.connection=model.kind==='email'?{smtp_host:model.smtpHost.trim(),smtp_port:model.smtpPort??0,smtp_user:model.smtpUser,smtp_password:model.smtpPassword,from:model.from.trim(),recipients,implicit_tls:model.implicitTLS}:{endpoint:model.endpoint.trim(),...(model.kind==='webhook'?{secret:model.secret,token:model.token}:model.kind==='feishu'||model.kind==='dingtalk'?{secret:model.secret}:{})}
  }
  emit('save',change)
}
</script>
<template>
  <Modal :open="true" :title="record?'配置通知渠道':'创建通知渠道'" :width="640" :footer="null" :mask-closable="false" :closable="!pending" :keyboard="!pending" @cancel="emit('close')">
    <a-alert v-if="error||formError" type="error" :message="error||formError" show-icon class="section-gap" />
    <a-form :model="model" layout="vertical" :disabled="pending" @finish="save">
      <div class="channel-fields"><a-form-item label="渠道名称" name="name" :rules="[{required:true,message:'请输入渠道名称'}]"><a-input v-model:value="model.name" :maxlength="128" /></a-form-item><a-form-item label="渠道类型" name="kind"><Select v-model:value="model.kind" :options="options" :disabled="pending||!!record" @keydown.esc.stop /></a-form-item></div>
      <a-form-item label="订阅内容" name="streams" :rules="[{required:true,type:'array',min:1,message:'请选择订阅内容'}]"><Select v-model:value="model.streams" aria-label="订阅内容" mode="multiple" :options="subscriptions" @keydown.esc.stop /></a-form-item>
      <a-form-item v-if="model.streams.includes('alerts')" label="告警级别" name="severities" :rules="[{required:true,type:'array',min:1,message:'请选择告警级别'}]"><Select v-model:value="model.severities" mode="multiple" :options="severityOptions" @keydown.esc.stop /></a-form-item>
      <div class="channel-fields"><a-form-item label="渠道启用" html-for="channel-enabled"><Switch id="channel-enabled" aria-label="渠道启用" v-model:checked="model.enabled" checked-children="启用" un-checked-children="停用" /></a-form-item><a-form-item label="静默截止时间" html-for="channel-mute"><a-input id="channel-mute" aria-label="静默截止时间" v-model:value="model.mutedUntil" :maxlength="40" placeholder="留空表示不静默，例如 2026-10-03T18:00:00+08:00" /></a-form-item></div>
      <Checkbox v-if="record" v-model:checked="updateConnection" :disabled="pending">更新连接信息</Checkbox>
      <p class="page-description section-gap">{{record&&!updateConnection?'保留已保存的连接信息和凭据。':'连接信息与凭据加密保存，保存后不回显。'}} {{model.kind.startsWith('syslog_')?'按订阅发送脱敏摘要；审计日志不包含操作原因或请求正文。':'按订阅发送安全告警或检测质量事件摘要。'}} 检测质量事件须显式选择，原生计数、配置摘要与报文载荷不外发。</p>
      <template v-if="updateConnection">
        <template v-if="model.kind==='email'">
          <div class="channel-fields"><a-form-item label="SMTP 主机" html-for="channel-smtp-host"><a-input id="channel-smtp-host" aria-label="SMTP 主机" v-model:value="model.smtpHost" :maxlength="253" placeholder="smtp.example.com" /></a-form-item><a-form-item label="SMTP 端口" html-for="channel-smtp-port"><InputNumber id="channel-smtp-port" aria-label="SMTP 端口" v-model:value="model.smtpPort" :min="1" :max="65535" :precision="0" style="width:100%" /></a-form-item></div>
          <div class="channel-fields"><a-form-item label="SMTP 账号" html-for="channel-smtp-user"><a-input id="channel-smtp-user" aria-label="SMTP 账号" v-model:value="model.smtpUser" :maxlength="320" autocomplete="off" /></a-form-item><a-form-item label="SMTP 密码" html-for="channel-smtp-password"><a-input-password id="channel-smtp-password" aria-label="SMTP 密码" v-model:value="model.smtpPassword" :maxlength="1024" autocomplete="new-password" /></a-form-item></div>
          <a-form-item label="发件地址" html-for="channel-from"><a-input id="channel-from" aria-label="发件地址" v-model:value="model.from" :maxlength="320" placeholder="security@example.com" /></a-form-item><a-form-item label="接收人" html-for="channel-recipients"><a-textarea id="channel-recipients" aria-label="接收人" v-model:value="model.recipients" :rows="3" :maxlength="32100" placeholder="填写邮箱地址，多个地址用逗号或换行分隔，最多 100 个。" /></a-form-item>
          <a-form-item label="TLS 连接方式" html-for="channel-tls"><Checkbox id="channel-tls" aria-label="TLS 连接方式" v-model:checked="model.implicitTLS">隐式 TLS</Checkbox><p class="page-description">未选择时使用必需的 STARTTLS；连接不支持 TLS 时停止投递。</p></a-form-item>
        </template>
        <template v-else>
          <a-form-item :label="model.kind.startsWith('syslog_')?'日志服务器地址':'Webhook 地址'" html-for="channel-endpoint"><a-input-password id="channel-endpoint" :aria-label="model.kind.startsWith('syslog_')?'日志服务器地址':'Webhook 地址'" v-model:value="model.endpoint" :maxlength="4096" autocomplete="new-password" :placeholder="model.kind.startsWith('syslog_')?'logs.example.com:6514':'https://example.com/webhook'" /></a-form-item>
          <a-form-item v-if="!model.kind.startsWith('syslog_')&&model.kind!=='wecom'" label="签名密钥" html-for="channel-secret"><a-input-password id="channel-secret" aria-label="签名密钥" v-model:value="model.secret" :maxlength="1024" autocomplete="new-password" placeholder="未启用签名校验时可留空" /></a-form-item>
          <a-form-item v-if="model.kind==='webhook'" label="Bearer Token" html-for="channel-token"><a-input-password id="channel-token" aria-label="Bearer Token" v-model:value="model.token" :maxlength="4096" autocomplete="new-password" placeholder="目标不要求认证时可留空" /></a-form-item>
          <a-alert v-if="model.kind.startsWith('syslog_')" type="info" message="Syslog 使用字节计数分帧。传输写入不代表日志服务器已落盘。" show-icon class="section-gap" />
        </template>
      </template>
      <div class="filter-actions channel-actions"><a-button :disabled="pending" @click="emit('close')">取消</a-button><a-button type="primary" html-type="submit" :loading="pending">保存渠道</a-button></div>
    </a-form>
  </Modal>
</template>
<style scoped>.channel-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--field-gap)}.channel-actions{justify-content:flex-end;margin-top:var(--section-gap)}@media(max-width:600px){.channel-fields{grid-template-columns:minmax(0,1fr);gap:0}}</style>
