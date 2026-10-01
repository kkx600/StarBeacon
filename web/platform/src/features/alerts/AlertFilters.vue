<script setup lang="ts">
import { Select as ASelect } from 'ant-design-vue'
import { reactive, shallowRef } from 'vue'
import type { SearchRequest } from '@starbeacon/shared/types.ts'
defineProps<{pending: boolean}>()
type Filters = Omit<SearchRequest,'start'|'end'|'page'|'page_size'>
const emit = defineEmits<{search: [filters: Filters, hours: number]}>()
const defaults: Filters = {keyword:'',source_ip:'',destination_ip:'',protocol:'',method:'',path:'',severity:''}
const form = reactive({...defaults}), hours = shallowRef(24)
function reset() {Object.assign(form,defaults); hours.value = 24; emit('search',{...form},hours.value)}
</script>
<template>
  <a-form class="panel filter-form" :model="form" layout="vertical" @finish="emit('search',{...form},hours)">
    <a-form-item label="关键词"><a-input v-model:value="form.keyword" placeholder="规则名称" allow-clear :maxlength="256" /></a-form-item>
    <a-form-item label="源 IP"><a-input v-model:value="form.source_ip" placeholder="完整 IP 地址" allow-clear /></a-form-item>
    <a-form-item label="目的 IP"><a-input v-model:value="form.destination_ip" placeholder="完整 IP 地址" allow-clear /></a-form-item>
    <a-form-item label="协议"><a-input v-model:value="form.protocol" placeholder="http、tcp、udp" allow-clear :maxlength="32" /></a-form-item>
    <a-form-item label="请求方法"><a-select v-model:value="form.method" :options="[{label:'全部方法',value:''},...['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].map(value => ({label:value,value}))]" /></a-form-item>
    <a-form-item label="路径前缀"><a-input v-model:value="form.path" placeholder="/api/" allow-clear :maxlength="1024" /></a-form-item>
    <a-form-item label="严重级别"><a-select v-model:value="form.severity" :options="[{label:'全部级别',value:''},{label:'高危',value:'high'},{label:'中危',value:'medium'},{label:'低危',value:'low'},{label:'未知',value:'unknown'}]" /></a-form-item>
    <a-form-item label="时间范围"><a-select v-model:value="hours" :options="[{label:'最近 24 小时',value:24},{label:'最近 7 天',value:168},{label:'最近 30 天',value:720}]" /></a-form-item>
    <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button :disabled="pending" @click="reset">重置</a-button></div>
  </a-form>
</template>
