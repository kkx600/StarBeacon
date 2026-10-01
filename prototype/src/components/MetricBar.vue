<script setup lang="ts">
import {computed} from 'vue'
import {formatQuantity} from '../../../web/packages/shared/src/utils/format'
import type {MetricSpec} from '../models'
const props=defineProps<{items:MetricSpec[]}>()
const displayed=computed(()=>props.items.map(item=>{if(!item.suffix||!/(?:B|bit\/s)$/.test(item.suffix))return item;const formatted=formatQuantity(`${item.value} ${item.suffix}`);const space=formatted.lastIndexOf(' ');return {...item,value:formatted.slice(0,space),suffix:formatted.slice(space+1)}}))
</script>
<template><div class="metric-bar"><div v-for="item in displayed" :key="item.label" class="metric-item" :class="item.tone"><span>{{item.label}}</span><strong :class="item.tone">{{item.value}}<small v-if="item.suffix">{{item.suffix}}</small></strong><small v-if="item.note" class="metric-note">{{item.note}}</small></div></div></template>
