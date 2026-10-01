<script setup lang="ts">
import {palette} from '../theme'
import {computed,ref,watch} from 'vue'
import {useRouter} from 'vue-router'
import type {EChartsCoreOption} from 'echarts/core'
import {FilterOutlined,DownloadOutlined} from '@ant-design/icons-vue'
import type {PageSpec,PreviewState} from '../models'
import {pageById} from '../data/catalog'
import {createFixtures} from '../data/fixtures'
import {exportJson} from '../composables/useRecords'
import PageHeader from '../components/PageHeader.vue'
import ChartPanel from '../components/ChartPanel.vue'
import StatePanel from '../components/StatePanel.vue'
import StatusTag from '../components/StatusTag.vue'
import RecordForm from '../components/RecordForm.vue'
import RecordDetail from '../components/RecordDetail.vue'
const props=defineProps<{page:PageSpec;state:PreviewState}>();const emit=defineEmits<{state:[value:PreviewState]}>();const router=useRouter()
const selected=ref('业务 API 节点');const scope=ref('全部网络域');const relationship=ref('通信与依赖');const detail=ref(false);const formOpen=ref(false)
const assetPage=pageById.get('assets')!;const assets=createFixtures(assetPage)
const record=computed(()=>assets.find(r=>r.name===selected.value)??assets[0]!)
const option=computed<EChartsCoreOption>(()=>({tooltip:{trigger:'item'},series:[{type:'graph',layout:'none',roam:false,symbolSize:55,label:{show:true,color:palette.recordText,position:'bottom',fontSize:13},lineStyle:{color:palette.controlBorder,width:1.8},edgeSymbol:['none','arrow'],edgeSymbolSize:6,data:[{name:'边界网关',x:180,y:160,itemStyle:{color:palette.primary},symbolSize:66},{name:'业务 API 节点',x:400,y:100,itemStyle:{color:palette.chartOrange}},{name:'订单数据库',x:650,y:100,itemStyle:{color:palette.muted}},{name:'身份服务',x:410,y:280,itemStyle:{color:palette.primary}},{name:'办公终端 A',x:170,y:340,itemStyle:{color:palette.teal}},{name:'研发构建节点',x:655,y:325,itemStyle:{color:palette.primary}},{name:'外部目的地',x:-10,y:110,itemStyle:{color:palette.danger},symbol:'roundRect',symbolSize:[70,48]}],links:[{source:'外部目的地',target:'边界网关'},{source:'边界网关',target:'业务 API 节点'},{source:'业务 API 节点',target:'订单数据库'},{source:'业务 API 节点',target:'身份服务'},{source:'办公终端 A',target:'身份服务'},{source:'研发构建节点',target:'身份服务'},{source:'边界网关',target:'办公终端 A'}]}]}))
watch(()=>props.state,state=>{detail.value=state==='detail';formOpen.value=state==='action'},{immediate:true})
function close(){detail.value=false;formOpen.value=false;if(['detail','action'].includes(props.state))emit('state','data')}
</script>
<template>
  <PageHeader title="风险拓扑" description="结合业务依赖和观测通信定位风险范围，关系保留来源与有效时间。"><a-space><a-select v-model:value="scope" class="select-domain" :options="['全部网络域','总部网络域','研发网络域'].map(value=>({value,label:value}))"/><a-button @click="formOpen=true"><FilterOutlined/>关系筛选</a-button><a-button @click="exportJson('topology',{synthetic:true,scope,relationship})"><DownloadOutlined/>导出</a-button></a-space></PageHeader>
  <a-alert message="拓扑关系为合成演示。通信关联不等于攻击传播；资产归属、代理和 NAT 需要按时间与来源核对。" type="info" show-icon class="page-notice"/>
  <StatePanel v-if="state==='loading'||state==='error'" :state="state" @action="emit('state','data')"/>
  <StatePanel v-else-if="state==='empty'" state="empty" title="尚未形成资产关系" description="接入资产、通信或授权业务依赖后，形成可追溯关系。" action="查看资产来源" @action="router.push('/page/assets')"/>
  <div v-else class="topology-layout"><section class="panel"><div class="panel-heading"><h2>{{scope}} · {{relationship}}</h2><span class="muted">7 个示例节点 / 7 条关系</span></div><ChartPanel :option="option" :height="480" label="资产与通信关系示例拓扑" @select="name=>selected=name"/><div class="topology-legend"><span><span class="status-dot info"></span>业务服务</span><span><span class="status-dot warning"></span>待核对风险</span><span><span class="status-dot danger"></span>外部目的地</span><span>箭头表示观测通信方向</span></div></section><aside class="panel topology-details"><div class="panel-heading"><h2>节点信息</h2><StatusTag :value="record.status"/></div><h3>{{selected}}</h3><a-descriptions :column="1" size="small"><a-descriptions-item label="资产编号">{{record.id}}</a-descriptions-item><a-descriptions-item label="IP 地址">{{record.ip}}</a-descriptions-item><a-descriptions-item label="资产组">{{record.group}}</a-descriptions-item><a-descriptions-item label="责任人">{{record.owner}}</a-descriptions-item><a-descriptions-item label="观测窗口">最近 24 小时</a-descriptions-item><a-descriptions-item label="关联告警">{{record.alerts}} 条示例</a-descriptions-item></a-descriptions><a-divider/><h3>依据与待办</h3><p>观测到异常请求。利用成功仍需应用与终端侧证据。</p><StatusTag value="结论待核对"/><a-button type="primary" block style="margin-top:20px" @click="detail=true">查看资产详情</a-button><a-button block style="margin-top:8px" @click="router.push('/page/incidents?state=action')">创建调查事件</a-button></aside></div>
  <RecordDetail :open="detail" :page="assetPage" :record="record" @close="close" @action="close();router.push('/page/assets?state=action')"/>
  <RecordForm :open="formOpen" :page="{...page,primary:'关系筛选',fields:[{key:'scope',label:'网络域',type:'select',required:true,value:scope,options:['全部网络域','总部网络域','研发网络域']},{key:'relationship',label:'关系类型',type:'select',required:true,value:relationship,options:['通信与依赖','业务依赖','身份关系']},{key:'window',label:'观测窗口',type:'select',required:true,value:'最近 24 小时',options:['最近 24 小时','最近 7 天']}]}" @close="close" @save="values=>{scope=String(values.scope);relationship=String(values.relationship);close()}"/>
</template>
