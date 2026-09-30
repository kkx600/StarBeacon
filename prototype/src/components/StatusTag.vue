<script setup lang="ts">
import {computed} from 'vue'
const props=defineProps<{value:unknown;level?:boolean}>()
const text=computed(()=>String(props.value??'未提供'))
const tone=computed(()=>/严重|高危|拒绝|失败|恶意|缺少|字节缺口/.test(text.value)?'danger':/未知|不足|不可|尚未|未核验|未验证|未确认|等待|待|离线|负载高|水位高|不完整|关注|中危|排队|降级|过期|仅元数据|条件|单向|部分/.test(text.value)?'warning':/成功|完成|正常|在线|核验|验证|生效|已连接|已审核|已送达|支持|完整|已撤销/.test(text.value)?'success':/运行|研判中|调查中|审批|灰度/.test(text.value)?'info':'neutral')
</script>
<template><span class="status-tag" :class="tone"><span class="status-dot" :class="tone"></span>{{text}}</span></template>
