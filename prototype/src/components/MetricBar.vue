<script setup lang="ts">
import type {MetricSpec} from '../models'
defineProps<{items:MetricSpec[]}>()
</script>
<template><div class="metric-bar"><div v-for="item in items" :key="item.label" class="metric-item" :class="item.tone"><span>{{item.label}}</span><strong :class="item.tone">{{item.value}}<small v-if="item.suffix">{{item.suffix}}</small></strong><small v-if="item.note" class="metric-note">{{item.note}}</small></div></div></template>
