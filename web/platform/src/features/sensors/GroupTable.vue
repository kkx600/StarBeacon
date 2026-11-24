<script setup lang="ts">
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import type { SensorGroup } from './management';
const props = defineProps<{ items: readonly SensorGroup[]; admin: boolean; locked: boolean }>();
const emit = defineEmits<{ edit: [group: SensorGroup]; members: [group: SensorGroup] }>();
const columns = [
  { title: '分组编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
  { title: '分组名称', dataIndex: 'name', width: 160, ellipsis: true },
  { title: '修订', dataIndex: 'revision', width: 62, className: 'technical' },
  { title: '分组状态', key: 'active', width: 100 },
  { title: '探针数量', key: 'members', width: 120 },
  { title: '说明', dataIndex: 'description', width: 240, ellipsis: true },
  { title: '更新时间', key: 'updated', width: 180 },
  { title: '操作', key: 'action', width: 180, fixed: 'right' as const },
];
function action(kind: 'edit' | 'members', id: string) {
  const item = props.items.find(g => g.id === id);
  if (!item) return;
  if (kind === 'edit') emit('edit', item);
  else emit('members', item);
}
</script>
<template>
  <ListTable :columns="columns" :data-source="[...items]" :scroll="{ x: 1182 }"
    ><template #bodyCell="{ column, record }">
      <StatusTag
        v-if="column.key === 'active'"
        :tone="record.active ? 'success' : 'neutral'"
        :value="record.active ? '启用' : '停用'"
      />
      <button v-else-if="column.key === 'members'" class="link-button" @click="action('members', record.id)">
        {{ record.member_count }} 台
      </button>
      <template v-else-if="column.key === 'updated'">{{ formatTime(record.updated_at) }}</template>
      <div v-else-if="column.key === 'action'" class="table-row-actions">
        <a-button type="link" size="small" @click="action('members', record.id)">查看探针</a-button>
        <a-button v-if="admin" type="link" size="small" :disabled="locked" @click="action('edit', record.id)"
          >编辑</a-button
        >
      </div>
    </template></ListTable
  >
</template>
