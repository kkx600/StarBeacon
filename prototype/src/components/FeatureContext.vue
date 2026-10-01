<script setup lang="ts">
import {palette,chartPalette} from '../theme'
import {computed} from 'vue'
import type {EChartsCoreOption} from 'echarts/core'
import type {PageSpec} from '../models'
import ChartPanel from './ChartPanel.vue'
const props=defineProps<{page:PageSpec}>()
const application= computed(()=>props.page.family==='application')
const latency=computed(()=>['metric','latency'].includes(props.page.family))
const option=computed<EChartsCoreOption>(()=>application.value?{
  color:chartPalette,tooltip:{trigger:'axis'},grid:{left:45,right:22,top:20,bottom:35},xAxis:{type:'category',data:['百度网盘','爱奇艺','企业微信','飞书','钉钉','其他']},yAxis:{type:'value',name:'GiB',splitLine:{lineStyle:{color:palette.chartGrid}}},series:[{type:'bar',data:[3.82,2.41,0.86,0.74,0.64,4.25],barWidth:28,itemStyle:{borderRadius:[3,3,0,0]}}]
}:{color:[palette.primary,palette.chartOrange],tooltip:{trigger:'axis'},legend:{bottom:0,itemWidth:12,itemHeight:4},grid:{left:45,right:22,top:20,bottom:65},xAxis:{type:'category',data:['采集检测','持久接收','可检索','通知接受','设备接受','配置读回']},yAxis:{type:'value',name:'ms',splitLine:{lineStyle:{color:palette.chartGrid}}},series:[{name:'P50',type:'bar',data:[4,18,240,480,210,630],barMaxWidth:20},{name:'P95',type:'bar',data:[12,48,710,1200,540,1300],barMaxWidth:20}]})
</script>
<template><section v-if="application||latency" class="panel feature-chart"><div class="panel-heading"><h2>{{application?'应用流量分布':'分段时延对比'}}</h2><span class="muted">合成示例 · {{application?'未知应用单独计量':'不含无起点样本'}}</span></div><ChartPanel :option="option" :height="220" :label="application?'应用产品流量合成示例':'告警与执行各阶段耗时合成示例'"/></section></template>
