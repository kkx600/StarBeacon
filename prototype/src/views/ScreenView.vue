<script setup lang="ts">
import {palette,screenChartPalette} from '../theme'
import {computed,ref,watch} from 'vue'
import {FullscreenOutlined,SettingOutlined,ArrowRightOutlined} from '@ant-design/icons-vue'
import {useRouter} from 'vue-router'
import type {EChartsCoreOption} from 'echarts/core'
import type {PageSpec,PreviewState} from '../models'
import {createFixtures} from '../data/fixtures'
import {pageById} from '../data/catalog'
import {useRecords} from '../composables/useRecords'
import {sensorThresholds as thresholds} from '../composables/useSensorHealth'
import {healthFor,sensorMetrics} from '../data/sensorHealth'
import ChartPanel from '../components/ChartPanel.vue'
import MetricBar from '../components/MetricBar.vue'
import StatePanel from '../components/StatePanel.vue'
import StatusTag from '../components/StatusTag.vue'
import RecordDetail from '../components/RecordDetail.vue'
import RecordForm from '../components/RecordForm.vue'
const props=defineProps<{page:PageSpec;state:PreviewState}>();const emit=defineEmits<{state:[value:PreviewState]}>();const router=useRouter();const root=ref<HTMLElement>();const detail=ref(false);const formOpen=ref(false);const scope=ref('全部网络域')
const alertPage=pageById.get('alerts')!;const alerts=createFixtures(alertPage).slice(0,5);const selectedAlert=ref(alerts[0]!)
const {records:sensors}=useRecords(pageById.get('sensors')!)
const observedSensors=computed(()=>props.state==='empty'?[]:sensors.value.filter(record=>scope.value==='全部网络域'||record.scope===scope.value))
const sensorSummary=computed(()=>sensorMetrics(observedSensors.value,thresholds))
const healthRecords=computed(()=>observedSensors.value.filter(record=>healthFor(record,thresholds)!=='正常'))
const metrics=computed(()=>[{label:'安全事件',value:props.state==='empty'?'0':'9'},{label:'高危告警',value:props.state==='empty'?'0':'12',tone:'danger' as const},{label:'在线探针',value:`${sensorSummary.value[1]!.value} / ${sensorSummary.value[0]!.value}`},{...sensorSummary.value[3]!},{label:'活动响应租约',value:props.state==='empty'?'0':'18'}])
const trend:EChartsCoreOption={color:[palette.screenBlue,palette.screenAmber],tooltip:{trigger:'axis'},grid:{left:40,right:15,top:20,bottom:35},legend:{bottom:0,textStyle:{color:palette.screenMuted},itemWidth:12,itemHeight:3},xAxis:{type:'category',data:['00:00','04:00','08:00','12:00','16:00','20:00','24:00'],axisLabel:{color:palette.screenMuted},axisLine:{lineStyle:{color:palette.screenLine}}},yAxis:{type:'value',axisLabel:{color:palette.screenMuted},splitLine:{lineStyle:{color:palette.screenLine}}},series:[{name:'原始告警',type:'line',areaStyle:{opacity:0.14},data:[18,26,42,128,76,48,32],smooth:0.25,symbolSize:5,lineStyle:{width:2.5}},{name:'高危及严重',type:'line',symbol:'diamond',data:[2,3,4,12,8,3,2],smooth:0.25,symbolSize:5,lineStyle:{width:2.5}}]}
const apps:EChartsCoreOption={color:[palette.screenBlue],tooltip:{trigger:'axis'},grid:{left:80,right:25,top:10,bottom:25},xAxis:{type:'value',axisLabel:{color:palette.screenMuted},splitLine:{lineStyle:{color:palette.screenLine}}},yAxis:{type:'category',data:['企业微信','飞书','爱奇艺','百度网盘'],axisTick:{show:false},axisLine:{show:false},axisLabel:{color:palette.screenMuted}},series:[{type:'bar',data:[0.86,0.74,2.41,3.82],barWidth:12}]}
const distribution:EChartsCoreOption={color:screenChartPalette,tooltip:{trigger:'item'},legend:{bottom:0,textStyle:{color:palette.screenMuted},itemWidth:9,itemHeight:9},series:[{type:'pie',radius:['40%','65%'],center:['50%','42%'],label:{show:false},data:[{name:'Web 异常',value:42},{name:'外连异常',value:28},{name:'身份尝试',value:18},{name:'其他',value:12}]}]}
watch(()=>props.state,state=>{detail.value=state==='detail';formOpen.value=state==='action'},{immediate:true})
function close(){detail.value=false;formOpen.value=false;if(['detail','action'].includes(props.state))emit('state','data')}
function fullscreen(){void root.value?.requestFullscreen?.()}
</script>
<template>
  <div ref="root" class="situation-screen"><header class="screen-header"><div><span class="screen-wordmark">星烽 StarBeacon</span><h1>安全态势大屏</h1></div><div><span>{{scope}} · 最近 24 小时</span><a-button ghost size="small" aria-label="配置大屏" @click="formOpen=true"><SettingOutlined/></a-button><a-button ghost size="small" aria-label="全屏展示" @click="fullscreen"><FullscreenOutlined/></a-button></div></header><MetricBar v-if="state!=='loading'&&state!=='error'" :items="metrics"/><StatePanel v-if="state==='loading'||state==='error'" :state="state" @action="emit('state','data')"/><StatePanel v-else-if="state==='empty'" state="empty" title="尚未形成态势数据" description="接入网络探针与授权数据源后显示风险与运营状态。" action="接入数据源" @action="router.push('/page/data-sources')"/><template v-else><div class="screen-grid"><section class="screen-panel screen-trend"><h2>告警与威胁趋势</h2><ChartPanel :option="trend" :height="260" label="大屏告警趋势合成示例" dark/></section><section class="screen-panel"><h2>威胁类型分布</h2><ChartPanel :option="distribution" :height="260" label="大屏威胁类型分布" dark/></section><section class="screen-panel"><h2>应用流量 <small>GiB · 规则识别</small></h2><ChartPanel :option="apps" :height="240" label="百度网盘爱奇艺等应用流量示例" dark/></section><section class="screen-panel screen-alerts"><h2>重点告警 <button @click="router.push('/page/alerts')">查看全部<ArrowRightOutlined/></button></h2><div v-for="alert in alerts" :key="alert.id" class="screen-alert"><StatusTag :value="alert.level"/><button @click="selectedAlert=alert;detail=true">{{alert.name}}<small>{{alert.source}} → {{alert.destination}}</small></button><span>{{alert.status}}</span></div></section><section class="screen-panel"><h2>探针与数据质量</h2><div class="screen-health"><div v-for="sensor in healthRecords" :key="sensor.id"><span>{{sensor.name}}</span><StatusTag :value="healthFor(sensor,thresholds)"/></div><div v-if="!healthRecords.length"><span>当前范围探针</span><StatusTag value="正常"/></div></div><p class="screen-caption">覆盖缺口影响结论范围，需补齐证据。</p></section><section class="screen-panel"><h2>响应与运营</h2><div class="screen-operations"><div><b>3</b><span>等待审批</span></div><div><b>1</b><span>结果未知</span></div><div><b>64</b><span>已撤销</span></div></div><p class="screen-caption">设备接受、配置读回与效果观察分别核对。</p></section></div></template><footer class="screen-footer"><span>合成示例 · 非实时数据</span><span>观测范围与数据来源决定结论边界</span><span>时间窗口：2026-09-30</span></footer></div>
  <RecordDetail :open="detail" :page="alertPage" :record="selectedAlert" @close="close" @action="close();router.push('/page/alerts?state=action')"/><RecordForm :open="formOpen" :page="{...page,fields:[{key:'scope',label:'展示范围',type:'select',required:true,value:scope,options:['全部网络域','总部网络域','研发网络域','分支网络域']},{key:'refresh',label:'刷新间隔（秒）',type:'number',required:true,value:30},{key:'access',label:'访问期限',type:'select',required:true,value:'1 小时',options:['1 小时','8 小时','1 天']}]}" @close="close" @save="values=>{scope=String(values.scope);close()}"/>
</template>
