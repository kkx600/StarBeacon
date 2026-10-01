<script setup lang="ts">
import { shallowRef } from 'vue'
import { message } from 'ant-design-vue'
import type { Sensor } from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import SensorTable from './SensorTable.vue'
import SensorDetail from './SensorDetail.vue'
import { useSensors } from './useSensors'
import { session } from '../../session'
const {items, pending, error, saving, refresh, toggle} = useSensors()
const selected = shallowRef<Sensor | null>(null)
async function change(sensor: Sensor) {try {await toggle(sensor); message.success('探针状态保存成功')} catch(e) {message.error(e instanceof Error ? e.message : '保存失败')}}
</script>
<template>
  <header class="page-header"><div><h1>探针管理</h1><p class="page-description">查看连接、资源、版本和待传队列，管理当前租户的探针。</p></div><a-button :loading="pending" @click="refresh">刷新</a-button></header>
  <section class="panel"><div class="panel-header"><h2>探针列表</h2><span>{{ items.length }} 台</span></div>
    <StatePanel :loading="pending" :error="error" :empty="items.length === 0" description="暂无探针，请完成采集器身份登记后连接平台。" @retry="refresh">
      <SensorTable :items="items" :admin="session.current.value?.role === 'admin'" :saving="saving" @view="selected = $event" @toggle="change" />
    </StatePanel>
  </section>
  <SensorDetail :sensor="selected" @close="selected = null" />
</template>
