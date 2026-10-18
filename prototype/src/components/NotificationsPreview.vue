<script setup lang="ts">
import {computed,ref,shallowRef,watch} from 'vue'
import {Descriptions as ADescriptions,Modal as AModal} from 'ant-design-vue'
import type {PreviewState} from '../models'
import PageHeader from './PageHeader.vue'
import StatePanel from '../../../web/packages/shared/src/components/StatePanel.vue'
import ChannelForm from '../../../web/platform/src/features/notifications/ChannelForm.vue'
import ChannelTable from '../../../web/platform/src/features/notifications/ChannelTable.vue'
import DeliveryTable from '../../../web/platform/src/features/notifications/DeliveryTable.vue'
import DeliveryDetail from '../../../web/platform/src/features/notifications/DeliveryDetail.vue'
import {channelNames,streamNames,type Channel,type Delivery,type ChannelChange} from '../../../web/platform/src/features/notifications/notifications'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{page:string;state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>()
const samples:Channel[]=[{id:'channel_example_alerts',revision:3,name:'安全值班通知（示例）',kind:'webhook',enabled:true,severities:['high','medium'],streams:['alerts'],target:'https://notify.example.test',has_secret:true,muted_until:null,updated_at:'2026-10-18T00:00:00Z'},{id:'channel_example_quality',revision:1,name:'检测质量通知（示例）',kind:'wecom',enabled:true,severities:[],streams:['quality'],target:'https://wecom.example.test',has_secret:true,muted_until:null,updated_at:'2026-10-18T00:00:00Z'},{id:'channel_example_syslog',revision:2,name:'运维日志转发（示例）',kind:'syslog_tls',enabled:true,severities:[],streams:['quality','operations','logins'],target:'logs.example.test:6514',has_secret:false,muted_until:null,updated_at:'2026-10-18T00:00:00Z'}]
const selected=shallowRef<Channel|null>(null),editing=shallowRef<Channel|null>(null),formOpen=shallowRef(false),deliveryOpen=shallowRef(false),keyword=ref('')
const channelRows=computed(()=>samples.filter(row=>(props.page!=='syslog-output'||row.kind==='syslog_tls')&&row.name.includes(keyword.value)))
const delivered:Delivery={id:'delivery_example',channel_id:'channel_example_quality',channel_name:'检测质量通知（示例）',kind:'wecom',channel_revision:1,recipient:'',state:'accepted',version:2,attempts:1,alert_count:0,record_count:1,stream:'quality',created_at:'2026-10-18T00:30:06.123456789Z',updated_at:'2026-10-18T00:30:07Z',receipt:{state:'accepted',code:'provider_accepted',duration_ms:126,observed_at:'2026-10-18T00:30:07Z'}}
const delivery=computed<Delivery>(()=>props.state==='action'?{...delivered,state:'uncertain',receipt:{code:'acknowledgment_lost',duration_ms:126}}:delivered)
const title=computed(()=>props.page==='syslog-output'?'Syslog 转发':props.page==='delivery-logs'?'推送日志':'通知渠道')
watch(()=>[props.page,props.state],()=>{selected.value=null;formOpen.value=false;deliveryOpen.value=false;if(props.state==='detail'){if(props.page==='delivery-logs')deliveryOpen.value=true;else selected.value=channelRows.value[0]??null}if(props.state==='action'){if(props.page==='delivery-logs')deliveryOpen.value=true;else{editing.value=props.page==='syslog-output'?channelRows.value[0]??null:null;formOpen.value=true}}},{immediate:true})
function edit(record:Channel){editing.value=record;formOpen.value=true}
function save(_change:ChannelChange){formOpen.value=false;emit('state','data')}
</script>
<template>
 <PageHeader :title="title" description="维护明确的订阅范围，核对渠道受理与传输结果。"><a-button v-if="page!=='delivery-logs'" type="primary" @click="editing=null;formOpen=true">创建通知渠道</a-button><a-button @click="emit('state','data')">刷新</a-button></PageHeader>
 <a-alert type="info" show-icon message="以下为合成示例，仅用于演示订阅范围与投递回执。此处不保存连接信息或发送通知。渠道受理、传输写入与实际送达分别记录；检测质量事件须显式订阅。" class="section-gap"/>
 <a-form layout="inline" class="panel notification-preview-filter" @finish="emit('state','data')"><a-form-item :label="page==='delivery-logs'?'投递标识':'渠道名称'"><a-input v-model:value="keyword" :maxlength="128" placeholder="输入查询关键词"/></a-form-item><a-button type="primary" html-type="submit">查询</a-button><a-button @click="keyword='';emit('state','data')">重置</a-button></a-form>
 <section class="panel"><StatePanel :loading="state==='loading'" :error="state==='error'?'通知数据读取失败，请稍后重试。':''" :empty="state==='empty'||page!=='delivery-logs'&&!channelRows.length" description="当前条件下没有记录，请调整查询或配置通知渠道。" @retry="emit('state','data')"><DeliveryTable v-if="page==='delivery-logs'" :items="[delivery]" @view="deliveryOpen=true"/><ChannelTable v-else :items="channelRows" :busy="false" available @edit="edit" @test="selected=$event"/></StatePanel></section>
 <ChannelForm v-if="formOpen" :record="editing" :pending="false" error="" :development="false" @save="save" @close="formOpen=false"/>
 <DeliveryDetail :record="deliveryOpen?delivery:null" :busy="false" @close="deliveryOpen=false" @retry="deliveryOpen=false;emit('state','data')"/>
 <a-modal v-if="selected" open title="通知渠道详情" :width="640" :footer="null" @cancel="selected=null"><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="渠道名称">{{selected.name}}</a-descriptions-item><a-descriptions-item label="渠道类型">{{channelNames[selected.kind]}}</a-descriptions-item><a-descriptions-item label="目标">{{selected.target}}</a-descriptions-item><a-descriptions-item label="订阅内容">{{selected.streams?.map(s=>streamNames[s]).join('、')}}</a-descriptions-item><a-descriptions-item label="配置修订">{{selected.revision}}</a-descriptions-item><a-descriptions-item label="凭据">{{selected.has_secret?'已保存，不回显':'未配置'}}</a-descriptions-item></a-descriptions><div class="filter-actions section-gap"><a-button type="primary" @click="edit(selected);selected=null">配置渠道</a-button><a-button @click="selected=null">关闭</a-button></div></a-modal>
</template>
<style scoped>.notification-preview-filter{display:flex;flex-wrap:wrap;align-items:center;gap:var(--related-gap);padding:var(--panel-inset);margin-bottom:var(--section-gap)}.notification-preview-filter .ant-form-item{margin:0}</style>
