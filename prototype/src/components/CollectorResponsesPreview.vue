<script setup lang="ts">
import {ref,watch} from 'vue'
import type {PreviewState} from '../models'
import StatePanel from './StatePanel.vue'
import StatusTag from './StatusTag.vue'
const props=defineProps<{state:PreviewState}>()
const emit=defineEmits<{state:[value:PreviewState]}>()
const columns=[{title:'连接器',dataIndex:'id',width:180},{title:'设备',dataIndex:'device',width:185},{title:'接口版本',dataIndex:'version',width:170},{title:'状态',key:'status',width:155},{title:'最长封禁',dataIndex:'ttl',width:110},{title:'核验时间',dataIndex:'observed',width:185},{title:'操作',key:'action',width:85}]
const rows=[{id:'connector_hq',device:'device_hq',version:'protocol-fixture/1',status:'设备已就绪（示例）',ttl:'3,600 秒',observed:'2026-09-30 09:45:00',sha:'d'.repeat(64)},{id:'connector_branch',device:'device_branch',version:'protocol-fixture/1',status:'设备不可用（示例）',ttl:'300 秒',observed:'2026-09-30 09:43:00',sha:'e'.repeat(64)}]
const selected=ref(rows[0]!),detail=ref(false),guide=ref(false)
watch(()=>props.state,value=>{detail.value=value==='detail';guide.value=value==='action'},{immediate:true})
function view(id:string){const value=rows.find(row=>row.id===id);if(value){selected.value=value;detail.value=true}}
function close(){detail.value=false;guide.value=false;if(props.state==='detail'||props.state==='action')emit('state','data')}
</script>
<template>
 <StatePanel v-if="state==='loading'||state==='error'" :state="state" :description="state==='error'?'设备目录未能读取，当前认证与配置状态未知。请刷新核对。':undefined" @action="emit('state','data')"/>
 <section v-else class="panel table-panel">
  <div class="table-toolbar"><h2>联动设备</h2><a-button @click="guide=true">查看配置说明</a-button></div>
  <a-alert type="info" show-icon message="设备目录为合成示例。采集器通过私有文件配置固定 HTTPS 接口与凭据引用，主控平台管理员提交限时任务。" class="page-notice"/>
  <StatePanel v-if="state==='empty'" state="empty" title="尚未登记联动设备" description="配置本机 HTTP 连接器，核对受信 CA、设备身份与原生到期能力后，向平台上报只读目录。" action="查看配置说明" @action="guide=true"/>
  <a-table v-else :columns="columns" :data-source="rows" row-key="id" size="middle" :pagination="false" :scroll="{x:1070}"><template #bodyCell="{column,record}"><StatusTag v-if="column.key==='status'" :value="record.status"/><a-button v-else-if="column.key==='action'" type="link" @click="view(record.id)">查看</a-button></template></a-table>
  <p class="collector-footnote">就绪观测超过 35 秒需重新核对。采集器控制台没有设备写入入口；旁路探针自身不阻断流量。</p>
 </section>
 <a-modal title="联动设备详情" :open="detail" :width="720" :footer="null" @cancel="close"><a-alert type="info" show-icon message="以下是合成协议目录，不是商业设备验收或流量阻断证明。" class="page-notice"/><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="连接器 / 设备">{{selected.id}} / {{selected.device}}</a-descriptions-item><a-descriptions-item label="接口版本">{{selected.version}}</a-descriptions-item><a-descriptions-item label="设备状态">{{selected.status}}</a-descriptions-item><a-descriptions-item label="配置摘要"><span class="technical" style="overflow-wrap:anywhere">{{selected.sha}}</span></a-descriptions-item><a-descriptions-item label="核验时间">{{selected.observed}}</a-descriptions-item><a-descriptions-item label="最长封禁">{{selected.ttl}}</a-descriptions-item><a-descriptions-item label="租约要求">原生绝对 TTL、独立租约、条件解除</a-descriptions-item></a-descriptions><p class="field-hint">同 IP 的不同租约分别到期或解除。写入结果未知时回读原租约，不延长原到期时间，不删除其他租约。</p><div class="collector-detail-footer"><a-button @click="close">关闭</a-button></div></a-modal>
 <a-modal title="连接器配置说明" :open="guide" :width="720" :footer="null" @cancel="close"><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="本机配置">SB_RESPONSE_CONNECTORS_FILE 指向 0600 权限的绝对文件路径</a-descriptions-item><a-descriptions-item label="管理接口">固定 HTTPS 管理 IP，受信证书须包含该 IP</a-descriptions-item><a-descriptions-item label="凭据引用">受信 CA 与私有 Bearer 文件；凭据不进入平台任务</a-descriptions-item><a-descriptions-item label="目标约束">单 IP、30–3600 秒、允许 / 保护网段、本机与平台管理通道保护</a-descriptions-item><a-descriptions-item label="追溯留存">默认 180 天，可配置；本机最多 1,024 条租约历史</a-descriptions-item><a-descriptions-item label="发起入口">主控平台 → 探针列表 → 查看 → 限时封禁</a-descriptions-item></a-descriptions><p class="field-hint">这是配置说明，没有执行保存、网络访问或设备动作。模型影子评估不能授权封禁；真实设备另行验收。</p><div class="collector-detail-footer"><a-button @click="close">关闭</a-button></div></a-modal>
</template>
