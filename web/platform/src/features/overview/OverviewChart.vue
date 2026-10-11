<script setup lang="ts">
import {onBeforeUnmount,onMounted,ref,watch} from 'vue'
import {init,use,type ECharts,type EChartsCoreOption} from 'echarts/core'
import {BarChart,LineChart} from 'echarts/charts'
import {GridComponent,TooltipComponent,AriaComponent} from 'echarts/components'
import {SVGRenderer} from 'echarts/renderers'
use([BarChart,LineChart,GridComponent,TooltipComponent,AriaComponent,SVGRenderer])
const props=defineProps<{option:EChartsCoreOption;label:string}>()
const element=ref<HTMLElement>();let chart:ECharts|undefined,observer:ResizeObserver|undefined
function render(){chart?.setOption({...props.option,animation:false,aria:{enabled:true,label:{description:props.label}},tooltip:{renderMode:'richText',confine:true}},true)}
onMounted(()=>{if(element.value){chart=init(element.value,undefined,{renderer:'svg'});render();observer=new ResizeObserver(()=>chart?.resize());observer.observe(element.value)}})
watch(()=>[props.option,props.label],render,{deep:true})
onBeforeUnmount(()=>{observer?.disconnect();chart?.dispose()})
</script>
<template><div ref="element" class="overview-chart" role="img" :aria-label="label"/></template>
<style scoped>.overview-chart{height:230px;width:100%;min-width:0}</style>
