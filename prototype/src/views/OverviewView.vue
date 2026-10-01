<script setup lang="ts">
import {palette,chartPalette} from '../theme'
import {computed,ref,watch} from 'vue'
import {useRouter} from 'vue-router'
import {ArrowRightOutlined,DownloadOutlined,FullscreenOutlined} from '@ant-design/icons-vue'
import type {EChartsCoreOption} from 'echarts/core'
import type {PageSpec,PreviewState} from '../models'
import {createFixtures} from '../data/fixtures'
import {exportJson,useRecords} from '../composables/useRecords'
import {sensorThresholds as thresholds} from '../composables/useSensorHealth'
import {sensorMetrics} from '../data/sensorHealth'
import PageHeader from '../components/PageHeader.vue'
import MetricBar from '../components/MetricBar.vue'
import ChartPanel from '../components/ChartPanel.vue'
import StatePanel from '../components/StatePanel.vue'
import StatusTag from '../components/StatusTag.vue'
import RecordForm from '../components/RecordForm.vue'
import RecordDetail from '../components/RecordDetail.vue'
import {pageById} from '../data/catalog'
const props=defineProps<{page:PageSpec;state:PreviewState}>();const emit=defineEmits<{state:[value:PreviewState]}>();const router=useRouter()
const time=ref('最近 24 小时');const domain=ref('全部网络域');const formOpen=ref(false);const detailOpen=ref(false)
const alertPage=pageById.get('alerts')!;const alerts=createFixtures(alertPage).slice(0,5);const selectedAlert=ref(alerts[0]!)
watch(()=>props.state,state=>{formOpen.value=state==='action';detailOpen.value=state==='detail'},{immediate:true})
const empty=computed(()=>props.state==='empty')
const {records:sensors}=useRecords(pageById.get('sensors')!)
const observedSensors=computed(()=>empty.value?[]:sensors.value.filter(record=>domain.value==='全部网络域'||record.scope===domain.value))
const sensorSummary=computed(()=>sensorMetrics(observedSensors.value,thresholds))
const metrics=computed(()=>[{label:'安全事件',value:empty.value?'0':'9',note:empty.value?'当前窗口无事件':'3 个等待接单 · 合成示例'},{label:'高危与严重告警',value:empty.value?'0':'12',tone:'danger' as const,note:'合成告警示例'},{label:'在线探针',value:`${sensorSummary.value[1]!.value} / ${sensorSummary.value[0]!.value}`,note:'当前网络域设备快照'},{...sensorSummary.value[2]!,label:'探针需要关注',note:'连接、资源与采集质量'},{...sensorSummary.value[3]!}])
const trend=computed<EChartsCoreOption>(()=>({color:[palette.primary,palette.chartOrange],tooltip:{trigger:'axis'},legend:{bottom:0,icon:'roundRect',itemWidth:12,itemHeight:3},grid:{top:15,left:45,right:16,bottom:42},xAxis:{type:'category',boundaryGap:false,data:['00:00','04:00','08:00','12:00','16:00','20:00','24:00'],axisLine:{lineStyle:{color:palette.line}},axisLabel:{color:palette.muted}},yAxis:{type:'value',splitLine:{lineStyle:{color:palette.chartGrid}},axisLabel:{color:palette.muted}},series:[{name:'原始告警',type:'line',smooth:0.2,symbolSize:5,lineStyle:{width:2.5},areaStyle:{opacity:0.12},data:domain.value==='全部网络域'?[18,26,42,128,76,48,32]:[8,12,21,58,42,18,14]},{name:'高危及严重',type:'line',smooth:0.2,symbol:'diamond',symbolSize:6,lineStyle:{width:2.5,type:'dashed'},data:[2,3,4,12,8,3,2]}]}))
const pie:EChartsCoreOption={color:chartPalette,tooltip:{trigger:'item'},legend:{orient:'vertical',right:12,top:'center',itemWidth:10,itemHeight:10,textStyle:{color:palette.muted}},series:[{type:'pie',radius:['44%','68%'],center:['32%','48%'],label:{show:false},data:[{name:'Web 异常',value:42},{name:'异常外连',value:28},{name:'身份尝试',value:18},{name:'横向访问',value:8},{name:'其他',value:4}]}]}
const risk:EChartsCoreOption={color:[palette.primary],tooltip:{trigger:'axis'},grid:{left:95,right:24,top:12,bottom:25},xAxis:{type:'value',max:100,splitLine:{lineStyle:{color:palette.chartGrid}},axisLabel:{color:palette.muted}},yAxis:{type:'category',data:['办公终端','研发服务','核心业务','管理网络'],axisTick:{show:false},axisLine:{show:false},axisLabel:{color:palette.muted}},series:[{type:'bar',data:[32,48,76,86],barWidth:14,itemStyle:{borderRadius:[0,3,3,0]}}]}
function close(){formOpen.value=false;detailOpen.value=false;if(['detail','action'].includes(props.state))emit('state','data')}
</script>
<template>
  <PageHeader title="态势总览" description="聚焦当前风险、观测覆盖与处置进度。"><a-space><a-select v-model:value="domain" class="select-domain" :options="['全部网络域','总部网络域','研发网络域'].map(value=>({value,label:value}))"/><a-select v-model:value="time" class="select-time" :options="['最近 24 小时','最近 7 天','最近 30 天'].map(value=>({value,label:value}))"/><a-button @click="exportJson('overview',{synthetic:true,scope:domain,window:time,metrics})"><DownloadOutlined/>导出</a-button><a-button type="primary" @click="router.push('/page/big-screen')"><FullscreenOutlined/>态势大屏</a-button></a-space></PageHeader>
  <MetricBar v-if="state!=='loading'&&state!=='error'" :items="metrics"/>
  <StatePanel v-if="state==='loading'||state==='error'" :state="state" @action="emit('state','data')"/>
  <StatePanel v-else-if="empty" state="empty" title="尚未形成态势数据" description="接入网络探针或授权数据源后，将显示告警、资产风险和观测覆盖。" action="接入数据源" @action="router.push('/page/data-sources')"/>
  <template v-else>
    <div v-if="Number(sensorSummary[2]!.value)>0" class="overview-notice"><span class="status-dot warning"></span><span><b>{{sensorSummary[2]!.value}} 个探针需要关注</b> · 请核对连接、资源与采集质量；覆盖缺口会限制安全结论范围。</span><a-button type="link" size="small" @click="router.push('/page/sensors')">查看探针<ArrowRightOutlined/></a-button></div>
    <div class="dashboard-grid"><section class="panel trend-panel"><div class="panel-heading"><h2>告警趋势</h2><span class="muted">{{time}} · 合成示例</span></div><ChartPanel :option="trend" label="原始告警与高危告警趋势" :height="235"/></section><section class="panel"><div class="panel-heading"><h2>威胁类型</h2><a-button type="link" size="small" @click="router.push('/page/alerts')">查看告警</a-button></div><ChartPanel :option="pie" label="告警类型分布" :height="235"/></section></div>
    <div class="dashboard-grid second-row"><section class="panel"><div class="panel-heading"><h2>重点告警</h2><a-button type="link" size="small" @click="router.push('/page/alerts')">全部告警<ArrowRightOutlined/></a-button></div><div class="overview-alert" v-for="alert in alerts" :key="alert.id"><StatusTag :value="alert.level"/><div><button class="record-link" @click="selectedAlert=alert;detailOpen=true">{{alert.name}}</button><small>{{alert.source}} → {{alert.destination}} · {{alert.time}}</small></div><StatusTag :value="alert.status"/></div></section><section class="panel"><div class="panel-heading"><h2>资产组风险</h2><span class="muted">待核对风险示例</span></div><ChartPanel :option="risk" label="资产组风险分布" :height="220"/></section></div>
    <div class="dashboard-grid third-row"><section class="panel"><div class="panel-heading"><h2>响应进度</h2><a-button type="link" size="small" @click="router.push('/page/actions')">动作中心<ArrowRightOutlined/></a-button></div><div class="response-stages"><div><strong>3</strong><span>等待审批</span></div><span class="stage-arrow">→</span><div><strong>18</strong><span>活动租约</span></div><span class="stage-arrow">→</span><div><strong class="warning">1</strong><span>结果未知</span></div><span class="stage-arrow">→</span><div><strong>64</strong><span>已撤销</span></div></div><small class="panel-footnote">接受、配置生效和效果观察分别核验。</small></section><section class="panel"><div class="panel-heading"><h2>运营待办</h2><span class="muted">当前值班组</span></div><div class="todo-list"><button @click="router.push('/page/assessments')"><span>告警等待复核</span><b>38</b><ArrowRightOutlined/></button><button @click="router.push('/page/reports')"><span>日报等待审核</span><b>1</b><ArrowRightOutlined/></button><button @click="router.push('/page/rule-tests')"><span>规则等待验证</span><b>3</b><ArrowRightOutlined/></button></div></section></div>
  </template>
  <RecordDetail :open="detailOpen" :page="alertPage" :record="selectedAlert" @close="close" @action="close();router.push('/page/alerts?state=action')"/>
  <RecordForm :open="formOpen" :page="{...page,fields:[{key:'scope',label:'统计范围',type:'select',required:true,value:'全部网络域',options:['全部网络域','总部网络域','研发网络域']},{key:'window',label:'时间窗口',type:'select',required:true,value:'最近 24 小时',options:['最近 24 小时','最近 7 天','最近 30 天']}],primary:'筛选态势'}" @close="close" @save="values=>{domain=String(values.scope);time=String(values.window);close()}"/>
</template>
