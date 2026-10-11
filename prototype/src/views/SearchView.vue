<script setup lang="ts">
import {computed,ref,watch} from 'vue'
import {message} from 'ant-design-vue'
import {SearchOutlined,QuestionCircleOutlined,DownloadOutlined,PlusOutlined,DeleteOutlined} from '@ant-design/icons-vue'
import type {PageSpec,PreviewState,BusinessRecord} from '../models'
import {packetRows,createFixtures,hasPacketEvidence} from '../data/fixtures'
import {pageById} from '../data/catalog'
import {exportCsv} from '../composables/useRecords'
import {compilePreviewFilter} from '../composables/previewFilter'
import PageHeader from '../components/PageHeader.vue'
import StatePanel from '../components/StatePanel.vue'
import PacketWorkbench from '../components/PacketWorkbench.vue'
import StatusTag from '../components/StatusTag.vue'
import SavedQueries from '../components/SavedQueries.vue'
import type {QuerySnapshot} from '../components/SavedQueries.vue'
const props=defineProps<{page:PageSpec;state:PreviewState}>();const emit=defineEmits<{state:[value:PreviewState]}>()
const defaultMode=props.page.id==='packets'?'packet':props.page.id==='payloads'?'session':'alert'
const mode=ref(defaultMode);const query=ref('ip.src == 198.51.100.24 and http.request.method == "GET"');const executed=ref('');const error=ref('');const help=ref(false);const detail=ref(false);const formOpen=ref(false);const editorMode=ref('dsl')
const timeWindow=ref('最近 24 小时'),snapshot=computed<QuerySnapshot>(()=>({dataset:mode.value==='alert'?'alerts':mode.value==='session'?'context':'packet',mode:'advanced',window:timeWindow.value,filter:query.value,terms:{}}))
function applySaved(value:QuerySnapshot){mode.value=value.dataset==='alerts'?'alert':value.dataset==='context'?'session':'packet';query.value=value.filter;timeWindow.value=value.window;editorMode.value='dsl';run()}
const conditions=ref([{field:'ip.src',operator:'==',value:'198.51.100.24'}]);const fields=['ip.src','ip.dst','eth.src','eth.dst','http.request.method','http.request.uri','tcp.flags.syn','tcp.stream','dns.qry.name','tls.handshake.extensions_server_name']
const alertPage=pageById.get('alerts')!;const records=createFixtures(alertPage);const selectedRecord=ref<BusinessRecord>(records[0]!)
function showDetail(record:BusinessRecord){selectedRecord.value=record;detail.value=true}
const examples=[{label:'HTTP 请求',value:'http.request.method == "GET" and http.request.uri contains "/admin"'},{label:'地址与方向',value:'ip.src == 198.51.100.24 and ip.dst == 10.20.1.15'},{label:'MAC 地址',value:'eth.src == 02:00:00:20:01:18'},{label:'TCP 握手',value:'tcp.flags.syn == 1'},{label:'域名检索',value:'tls.handshake.extensions_server_name contains "example.test"'}]
const filtered=computed(()=>{if(props.state==='empty')return[];if(!executed.value)return records;return records.filter(compilePreviewFilter(executed.value))})
const appliedWindow=ref(timeWindow.value)
const exportSnapshot=ref<{filter:string;window:string;mode:string;records:BusinessRecord[]}|null>(null),exportError=ref('')
function openExport(){exportError.value='';exportSnapshot.value={filter:executed.value,window:appliedWindow.value,mode:mode.value,records:filtered.value.map(value=>({...value}))}}
function downloadExport(){if(!exportSnapshot.value)return;try{exportCsv(alertPage,exportSnapshot.value.records);exportSnapshot.value=null}catch(value){exportError.value=value instanceof Error?value.message:'示例文件无法生成'}}
const columns=[{title:'告警名称',dataIndex:'name',key:'name',width:220},{title:'严重级别',dataIndex:'level',key:'level',width:100},{title:'源 IP',dataIndex:'source',width:148},{title:'目的 IP',dataIndex:'destination',width:145},{title:'协议',dataIndex:'protocol',width:80},{title:'请求方法',dataIndex:'method',width:90},{title:'Path',dataIndex:'path',width:180},{title:'发生时间',dataIndex:'time',width:178},{title:'操作',key:'action',width:80,fixed:'right' as const}]
watch(()=>props.state,state=>{detail.value=state==='detail';formOpen.value=state==='action'},{immediate:true})
function run(){
  error.value=''
  if(editorMode.value==='visual')query.value=conditions.value.map(c=>`${c.field} ${c.operator} ${/^\d/.test(c.value)?c.value:JSON.stringify(c.value)}`).join(' and ')
  const open=(query.value.match(/\(/g)??[]).length;const close=(query.value.match(/\)/g)??[]).length
  if(open!==close){error.value='括号未配对。请核对表达式。';return}
  if(/;|\b(?:DELETE|INSERT|DROP)\b/i.test(query.value)){error.value='不支持此查询语句。请使用当前模式的字段与过滤运算符。';return}
  const queried=[...query.value.matchAll(/([a-zA-Z_]\w*(?:\.\w+)+)\s*(?:==|!=|>=|<=|>|<|contains|matches|in)/g)].map(m=>m[1]!)
  const unknown=queried.find(f=>!fields.includes(f))
  if(unknown){error.value=`字段 ${unknown} 未在当前示例字段目录中。请查看字段支持范围。`;return}
  try{compilePreviewFilter(query.value)}catch(cause){error.value=cause instanceof Error?cause.message:'无法解析示例表达式。';return}
  executed.value=query.value;appliedWindow.value=timeWindow.value;emit('state','data');message.success('已应用合成示例筛选。完整语义由平台检索服务实现。')
}
function close(){detail.value=false;formOpen.value=false;if(['detail','action'].includes(props.state))emit('state','data')}
</script>
<template>
  <PageHeader :title="page.title" :description="page.description"><a-space wrap><a-button @click="help=true"><QuestionCircleOutlined/>语法帮助</a-button><a-button :disabled="mode==='packet'||state==='loading'||state==='error'||!!error" @click="openExport"><DownloadOutlined/>导出</a-button><SavedQueries :snapshot="snapshot" :create-open="formOpen" @close="close" @apply="applySaved"/></a-space></PageHeader>
  <section class="panel search-editor"><div class="panel-heading"><a-segmented v-model:value="mode" :options="[{label:'告警索引',value:'alert'},{label:'会话与事务',value:'session'},{label:'原生数据包',value:'packet'}]"/><a-segmented v-model:value="editorMode" size="small" :options="[{label:'表达式',value:'dsl'},{label:'可视化',value:'visual'}]"/></div>
    <div v-if="editorMode==='dsl'" class="query-input"><span class="query-line-number">1</span><a-textarea v-model:value="query" :rows="2" spellcheck="false" placeholder="输入受支持的 Wireshark 风格表达式" aria-label="高级检索表达式"/></div>
    <div v-else class="visual-query"><div v-for="(condition,i) in conditions" :key="i"><span class="condition-prefix">{{i?'AND':'条件'}}</span><a-select v-model:value="condition.field" :options="fields.map(value=>({value,label:value}))"/><a-select v-model:value="condition.operator" :options="['==','!=','contains','matches','in'].map(value=>({value,label:value}))"/><a-input v-model:value="condition.value" placeholder="匹配值"/><a-button type="text" :disabled="conditions.length===1" aria-label="删除条件" @click="conditions.splice(i,1)"><DeleteOutlined/></a-button></div><a-button type="dashed" size="small" @click="conditions.push({field:'ip.dst',operator:'==',value:'10.20.1.15'})"><PlusOutlined/>添加条件</a-button></div>
    <a-alert v-if="error" :message="error" type="error" show-icon style="margin-top:12px"/>
    <div class="query-footer"><div class="query-examples"><span>示例</span><button v-for="example in examples.slice(0,4)" :key="example.label" @click="query=example.value;editorMode='dsl'">{{example.label}}</button></div><a-space><a-select v-model:value="timeWindow" :options="['最近 24 小时','最近 7 天','最近 30 天'].map(value=>({value,label:value}))" style="width:145px"/><a-button type="primary" @click="run"><SearchOutlined/>执行检索</a-button></a-space></div>
  </section>
  <a-alert :message="mode==='packet'?'原生包模式按授权 PCAP 执行。当前显示 8 帧合成样例；不提供缺失包、虚构出站时间或密文解密。':'事件索引模式只查询已投影字段；原生包字段需切换模式。当前原型演示查询编辑、校验和示例筛选。'" type="info" show-icon class="page-notice"/>
  <section class="panel table-panel"><div class="table-toolbar"><div><h2>检索结果</h2><span class="muted">{{mode==='packet'?8:filtered.length}} 条示例记录</span></div><a-space><a-tag>snapshot-demo-search</a-tag><a-button size="small" @click="query='';executed='';error=''">清除条件</a-button></a-space></div>
    <StatePanel v-if="state==='loading'||state==='error'" :state="state" @action="emit('state','data')"/>
    <StatePanel v-else-if="state==='empty'" state="empty" title="没有匹配的检索结果" description="请调整时间、网络域或表达式。未捕获、未投影和过期数据不会作为零风险依据。" action="清除条件" @action="query='';executed='';emit('state','data')"/>
    <PacketWorkbench v-else-if="mode==='packet'||page.id==='payloads'" :packets="packetRows"/>
    <a-table v-else :columns="columns" :data-source="filtered" row-key="id" :scroll="{x:1320}" :pagination="{pageSize:8,showTotal:(total:number)=>`共 ${total} 条`}" size="middle"><template #bodyCell="{column,record,text}"><button v-if="column.key==='name'" class="record-link" @click="showDetail(record)">{{text}}</button><StatusTag v-else-if="column.key==='level'" :value="text"/><a-button v-else-if="column.key==='action'" type="link" size="small" @click="showDetail(record)">查看</a-button><span v-else :class="{mono:['source','destination','path','method'].includes(column.dataIndex)}">{{text}}</span></template></a-table>
  </section>
  <a-modal :open="detail" title="通信证据" :width="1200" :footer="null" destroy-on-close @cancel="close"><div class="detail-heading"><div><div class="detail-id">{{selectedRecord.session??'未关联会话'}} · 合成示例</div><h2>{{selectedRecord.name}}</h2></div><StatusTag value="利用成功无法判定"/></div><PacketWorkbench v-if="hasPacketEvidence(selectedRecord)" :packets="packetRows"/><StatePanel v-else state="empty" title="未提供关联原生会话" description="当前合成记录只有协议元数据。不能将无关会话作为调查证据。" action="返回检索" @action="close"/></a-modal>
  <a-modal :open="!!exportSnapshot" title="导出检索结果" :width="640" :footer="null" :mask-closable="false" @cancel="exportSnapshot=null"><template v-if="exportSnapshot"><p class="muted">{{exportSnapshot.window}} · {{exportSnapshot.mode==='alert'?'告警记录':'协议记录'}}</p><dl v-if="exportSnapshot.filter" class="export-conditions" aria-label="导出筛选条件"><dt>高级表达式</dt><dd>{{exportSnapshot.filter}}</dd></dl><p v-else class="muted">未设置其他筛选条件，导出范围为上述时间窗口内的全部示例记录。</p><a-alert type="info" show-icon message="当前导出合成元数据示例，最多 10,000 条、8 MiB，不含原始载荷或原包。工程页面使用固定查询快照，超限不生成部分文件。"/><p class="muted">CSV 使用 UTF-8；公式前缀和长整数按文本保存。当前原型不会创建 Elasticsearch 快照或访问真实记录。</p><a-alert v-if="exportError" type="error" show-icon :message="exportError"/><div class="form-actions"><a-button @click="exportSnapshot=null">关闭</a-button><a-button type="primary" @click="downloadExport">导出 CSV</a-button></div></template></a-modal>
  <a-modal v-model:open="help" title="高级检索语法与范围" :footer="null" :width="860"><a-alert message="采用 Wireshark 风格；索引与原生包的支持范围不同。字段和运算符按版本能力清单执行，无法支持的语义不会静默删除。" type="info" show-icon/><a-table style="margin-top:16px" size="small" :pagination="false" :columns="[{title:'能力',dataIndex:'name'},{title:'示例',dataIndex:'example'},{title:'范围',dataIndex:'scope'}]" :data-source="[{key:1,name:'布尔与分组',example:'and / or / not / (...)',scope:'按模式支持'},{key:2,name:'比较与存在',example:'== / != / > / >= / < / <= / 字段',scope:'类型校验'},{key:3,name:'字符串与正则',example:'contains / matches',scope:'有界正则'},{key:4,name:'集合与地址',example:'in { ... } / CIDR',scope:'按字段类型'},{key:5,name:'字节与层',example:'切片 / 协议层索引',scope:'原生包能力清单'},{key:6,name:'多值字段',example:'any / all 比较语义',scope:'显式语义'}]"/><div class="detail-section"><h3>示例表达式</h3><pre v-for="example in examples" :key="example.label" class="code-example">{{example.value}}</pre></div><small class="muted">当前交互原型不实现完整 Wireshark 解析器。生产语义见高级检索与数据包取证设计。</small></a-modal>
</template>

<style scoped>.export-conditions{max-height:180px;overflow:auto;margin:12px 0;font-size:12px;line-height:1.7}.export-conditions dt{color:var(--muted)}.export-conditions dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}</style>
