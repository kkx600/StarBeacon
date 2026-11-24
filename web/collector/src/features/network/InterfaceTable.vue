<script setup lang="ts">
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import { statusTerms } from '@starbeacon/shared/terms.ts';
import type { NetworkInterface } from '@starbeacon/shared/types.ts';
defineProps<{ items: NetworkInterface[] }>();
const columns = [
  { title: '网卡名称', dataIndex: 'name', width: 140, className: 'technical', ellipsis: true },
  { title: '状态', key: 'status', width: 100 },
  { title: 'MAC 地址', key: 'mac', width: 180 },
  { title: 'IP 地址', key: 'addresses', width: 260, ellipsis: true },
  { title: 'MTU', dataIndex: 'mtu', width: 100 },
  { title: '接口用途', key: 'purpose', width: 100 },
];
</script>
<template>
  <ListTable
    :columns="columns"
    :data-source="items"
    row-key="name"
    :pagination="tablePagination()"
    :scroll="{ x: 880 }"
  >
    <template #bodyCell="{ column, record }">
      <StatusTag
        v-if="column.key === 'status'"
        :value="record.up ? '启用' : '停用'"
        :tone="record.up ? statusTerms.启用 : statusTerms.停用"
      />
      <span v-else-if="column.key === 'mac'" class="technical">{{ record.mac || '未提供' }}</span>
      <span v-else-if="column.key === 'addresses'" class="technical" :title="record.addresses.join('、')">{{
        record.addresses.join('、') || '未配置'
      }}</span>
      <span v-else-if="column.key === 'purpose'">{{ record.loopback ? '回环' : '网络接口' }}</span>
    </template>
  </ListTable>
</template>
