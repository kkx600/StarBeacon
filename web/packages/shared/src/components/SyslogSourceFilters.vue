<script setup lang="ts">
import type {SourceQuery} from '../syslog'
defineProps<{model:SourceQuery;pending:boolean}>()
const emit=defineEmits<{search:[];reset:[]}>()
</script>
<template><form class="panel source-filters" aria-label="Syslog 来源筛选" @submit.prevent="emit('search')"><label>接入探针<a-input v-model:value="model.sensor_id" aria-label="日志接入探针" allow-clear :maxlength="64"/></label><label>来源标识<a-input v-model:value="model.source_id" aria-label="Syslog 来源标识" allow-clear :maxlength="64"/></label><div class="filter-actions"><a-button html-type="submit" type="primary" :disabled="pending">查询</a-button><a-button :disabled="pending" @click="emit('reset')">重置</a-button></div></form></template>
<style scoped>.source-filters{display:flex;flex-wrap:wrap;align-items:flex-end;gap:var(--field-gap);padding:var(--panel-inset);margin-bottom:var(--section-gap)}.source-filters label{display:grid;gap:var(--related-gap);flex:1 1 190px;min-width:0;color:var(--muted)}</style>
