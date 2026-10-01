<script setup lang="ts">
import { Table as ATable } from 'ant-design-vue'
import { shallowRef } from 'vue'
import type { NetworkInterface } from '@starbeacon/shared/types.ts'
defineProps<{items:NetworkInterface[]}>()
const page = shallowRef(1), pageSize = shallowRef(10)
const columns=[{title:'网卡名称',dataIndex:'name',width:140},{title:'状态',key:'status',width:100},{title:'MAC 地址',key:'mac',width:180},{title:'IP 地址',key:'addresses',width:260},{title:'MTU',dataIndex:'mtu',width:100},{title:'接口用途',key:'purpose',width:100}]
</script>
<template>
  <div class="table-wrap">
    <a-table :columns="columns" :data-source="items" row-key="name" :pagination="{current: page, pageSize, total: items.length, showSizeChanger: true, pageSizeOptions: ['10', '20'], showTotal: (total: number) => `共 ${total} 个接口`, onChange: (current: number, size: number) => {page = current; pageSize = size}}" :scroll="{x:880, y:360}">
      <template #bodyCell="{column,record}">
        <span v-if="column.key==='status'" class="status" :class="record.up?'status-online':'status-offline'">{{ record.up?'启用':'关闭' }}</span>
        <span v-else-if="column.key==='mac'" class="technical">{{ record.mac || '未提供' }}</span>
        <span v-else-if="column.key==='addresses'" class="technical">{{ record.addresses.join('、') || '未配置' }}</span>
        <span v-else-if="column.key==='purpose'">{{ record.loopback?'回环':'网络接口' }}</span>
      </template>
    </a-table>
  </div>
</template>
