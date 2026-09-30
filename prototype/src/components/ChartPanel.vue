<script setup lang="ts">
import {onBeforeUnmount,onMounted,ref,watch} from 'vue'
import * as echarts from 'echarts/core'
import {BarChart,LineChart,PieChart,GraphChart,HeatmapChart} from 'echarts/charts'
import {TooltipComponent,GridComponent,LegendComponent,GraphicComponent,AriaComponent} from 'echarts/components'
import {SVGRenderer} from 'echarts/renderers'
import type {EChartsCoreOption} from 'echarts/core'
echarts.use([BarChart,LineChart,PieChart,GraphChart,HeatmapChart,TooltipComponent,GridComponent,LegendComponent,GraphicComponent,AriaComponent,SVGRenderer])
const props=withDefaults(defineProps<{option:EChartsCoreOption;height?:number;label:string;dark?:boolean}>(),{height:250})
const emit=defineEmits<{select:[name:string]}>()
const element=ref<HTMLDivElement>();let chart:echarts.ECharts|undefined;let observer:ResizeObserver|undefined
function render(){chart?.setOption({animation:false,aria:{enabled:true},...props.option},true)}
onMounted(()=>{if(element.value){chart=echarts.init(element.value,undefined,{renderer:'svg'});render();chart.on('click',params=>emit('select',params.name));observer=new ResizeObserver(()=>chart?.resize());observer.observe(element.value)}})
watch(()=>props.option,render,{deep:true})
onBeforeUnmount(()=>{observer?.disconnect();chart?.dispose()})
</script>
<template><div ref="element" class="chart-canvas" :style="{height:`${height}px`}" role="img" :aria-label="label"/></template>
