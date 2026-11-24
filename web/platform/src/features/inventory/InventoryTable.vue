<script setup lang="ts">
import { computed } from 'vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTerms } from '@starbeacon/shared/terms.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { criticalityNames, purposeNames, type InventoryKind, type InventoryRecord } from './inventory';
const props = defineProps<{ kind: InventoryKind; records: InventoryRecord[]; editable: boolean }>();
const emit = defineEmits<{ edit: [record: InventoryRecord]; view: [record: InventoryRecord] }>();
const columns = computed(() => [
  { title: '编号', dataIndex: 'id', width: 145, className: 'technical', ellipsis: true },
  { title: '名称', key: 'name', width: 190, ellipsis: true },
  { title: '修订', dataIndex: 'revision', width: 65 },
  ...(props.kind === 'assets'
    ? [
        { title: '网络接口', key: 'interfaces', width: 225, ellipsis: true, className: 'technical' },
        { title: '重要性', key: 'criticality', width: 90 },
      ]
    : props.kind === 'networks'
      ? [
          { title: '网段', key: 'prefix', width: 160, className: 'technical', ellipsis: true },
          { title: '用途', key: 'purpose', width: 130 },
        ]
      : [{ title: '责任人', key: 'owner', width: 160, ellipsis: true }]),
  { title: '状态', key: 'active', width: 90 },
  { title: '更新时间', key: 'updated_at', width: 180 },
  { title: '操作', key: 'actions', width: 110, fixed: 'right' as const },
]);
function interfaces(record: InventoryRecord) {
  return (
    record.data.interfaces?.map(row => `${row.name} · ${row.ips.join('、') || row.mac || '无地址'}`).join('；') ||
    '未配置'
  );
}
</script>
<template>
  <ListTable :data-source="records" :columns="columns" :scroll="{ x: 1060 }">
    <template #bodyCell="{ column, record }">
      <button v-if="column.key === 'name'" class="record-link" :title="record.data.name" @click="emit('view', record)">
        {{ record.data.name }}
      </button>
      <StatusTag
        v-else-if="column.key === 'active'"
        :value="record.data.active ? '启用' : '停用'"
        :tone="record.data.active ? statusTerms.启用 : statusTerms.停用"
      />
      <span v-else-if="column.key === 'updated_at'">{{ formatTime(record.updated_at) }}</span>
      <span v-else-if="column.key === 'criticality'">{{
        criticalityNames[record.data.criticality ?? ''] ?? '未指定'
      }}</span>
      <span v-else-if="column.key === 'purpose'">{{ purposeNames[record.data.purpose ?? ''] ?? '未指定' }}</span>
      <span v-else-if="column.key === 'interfaces'" :title="interfaces(record)">{{ interfaces(record) }}</span>
      <span v-else-if="column.key === 'prefix'" :title="record.data.prefix">{{ record.data.prefix || '未配置' }}</span>
      <span v-else-if="column.key === 'owner'" :title="record.data.owner">{{ record.data.owner || '未指定' }}</span>
      <div v-else-if="column.key === 'actions'" class="filter-actions">
        <button class="link-button" @click="emit('view', record)">查看</button
        ><button v-if="editable" class="link-button" @click="emit('edit', record)">编辑</button>
      </div>
    </template>
  </ListTable>
</template>
