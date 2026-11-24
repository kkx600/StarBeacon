<script setup lang="ts">
import { Popconfirm as APopconfirm } from 'ant-design-vue';
import type { Sensor } from '@starbeacon/shared/types.ts';
import { formatTime, formatPercent } from '@starbeacon/shared/types.ts';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { sensorConnectionTones, statusTone } from '@starbeacon/shared/statusTones.ts';
const props = defineProps<{ items: readonly Sensor[]; admin: boolean; saving: boolean }>();
const emit = defineEmits<{ view: [sensor: Sensor]; toggle: [sensor: Sensor]; edit: [sensor: Sensor] }>();
function action(kind: 'view' | 'toggle' | 'edit', id: string) {
  const sensor = props.items.find(item => item.id === id);
  if (sensor) {
    if (kind === 'view') emit('view', sensor);
    else if (kind === 'edit') emit('edit', sensor);
    else emit('toggle', sensor);
  }
}
const labels = { online: '在线', offline: '离线', disabled: '停用' };
const columns = [
  { title: '探针编号', dataIndex: 'id', width: 145, className: 'technical', ellipsis: true },
  { title: '探针名称', key: 'name', width: 155, ellipsis: true },
  { title: '分组', key: 'group', width: 100, ellipsis: true },
  { title: '站点', key: 'site', width: 98, ellipsis: true },
  { title: '连接状态', key: 'status', width: 86 },
  { title: 'CPU', key: 'cpu', width: 70 },
  { title: '内存', key: 'memory', width: 70 },
  { title: '磁盘', key: 'disk', width: 70 },
  { title: '版本', key: 'version', width: 70, className: 'technical', ellipsis: true },
  { title: '最后观测时间', key: 'seen', width: 162 },
  { title: '操作', key: 'action', width: 156, fixed: 'right' as const },
];
</script>
<template>
  <ListTable :columns="columns" :data-source="[...items]" :scroll="{ x: 1182 }">
    <template #bodyCell="{ column, record }">
      <button
        v-if="column.key === 'name'"
        type="button"
        class="record-link"
        :title="record.name"
        @click="action('view', record.id)"
      >
        {{ record.name }}
      </button>
      <StatusTag
        v-else-if="column.key === 'status'"
        :tone="statusTone(sensorConnectionTones, record.status)"
        :value="labels[record.status]"
      />
      <span v-else-if="column.key === 'group'" :title="record.group_name">{{
        record.group_name || (record.group_id ? '分组名称待核查' : '未分组')
      }}</span>
      <span v-else-if="column.key === 'site'" :title="record.site">{{ record.site || '未填写站点' }}</span>
      <template v-else-if="column.key === 'cpu'">{{ formatPercent(record.health.cpu_percent) }}</template>
      <template v-else-if="column.key === 'memory'">{{ formatPercent(record.health.memory_percent) }}</template>
      <template v-else-if="column.key === 'disk'">{{ formatPercent(record.health.disk_percent) }}</template>
      <span v-else-if="column.key === 'version'" :title="record.health.version">{{
        record.health.version || '—'
      }}</span>
      <template v-else-if="column.key === 'seen'">{{ formatTime(record.last_seen) }}</template>
      <div v-else-if="column.key === 'action'" class="table-row-actions">
        <a-button type="link" size="small" @click="action('view', record.id)">查看</a-button
        ><a-button
          v-if="admin"
          type="link"
          size="small"
          :disabled="saving || !record.metadata_revision"
          @click="action('edit', record.id)"
          >编辑</a-button
        ><a-popconfirm
          v-if="admin"
          ok-text="确定"
          cancel-text="取消"
          :title="record.active ? '停用后将拒绝探针上报和控制连接，确认停用？' : '确认启用此探针？'"
          @confirm="action('toggle', record.id)"
          ><a-button type="link" size="small" :disabled="saving">{{
            record.active ? '停用' : '启用'
          }}</a-button></a-popconfirm
        >
      </div>
    </template>
  </ListTable>
</template>
