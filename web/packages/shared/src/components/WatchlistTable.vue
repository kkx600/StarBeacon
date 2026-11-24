<script setup lang="ts">
import { computed } from 'vue';
import { Dropdown as ADropdown, Menu as AMenu } from 'ant-design-vue';
import ListTable from './ListTable.vue';
import { tablePagination } from '../pagination';
import StatusTag from './StatusTag.vue';
import type { StatusTone } from '../terms';
import {
  watchlistKinds,
  watchlistMatchTypes,
  watchlistState,
  watchlistStates,
  type WatchlistRecord,
} from '../watchlists';
import { formatTime } from '../types';
const props = defineProps<{
  items: readonly WatchlistRecord[];
  canEdit: boolean;
  disabled?: boolean;
  now?: number;
  paginate?: boolean;
}>();
const emit = defineEmits<{
  inspect: [record: WatchlistRecord];
  edit: [record: WatchlistRecord];
  preview: [record: WatchlistRecord];
  state: [record: WatchlistRecord];
}>();
const rows = computed(() => [...props.items]);
const AMenuItem = AMenu.Item;
const columns = [
  { title: '名单编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
  { title: '名单名称', key: 'name', width: 140, ellipsis: true },
  { title: '名单类型', key: 'kind', width: 100 },
  { title: '匹配方式', key: 'match', width: 100 },
  { title: '匹配值', key: 'values', width: 200, ellipsis: true },
  { title: '探针范围', key: 'scope', width: 120 },
  { title: '生效时间', key: 'start', width: 172, className: 'technical' },
  { title: '到期时间', key: 'end', width: 172, className: 'technical' },
  { title: '当前状态', key: 'state', width: 110 },
  { title: '修订', dataIndex: 'revision', width: 70 },
  { title: '操作', key: 'actions', width: 170, fixed: 'right' as const },
];
const tones = {
  disabled: 'neutral',
  scheduled: 'info',
  expired: 'neutral',
  effective: 'success',
} as const satisfies Record<keyof typeof watchlistStates, StatusTone>;
function stateBadge(row: WatchlistRecord) {
  const state = watchlistState(row, props.now);
  return { tone: tones[state], value: watchlistStates[state] };
}
function matchValues(row: WatchlistRecord) {
  const values = row.definition.values;
  return values.slice(0, 2).join('、') + (values.length > 2 ? ' · 另 ' + (values.length - 2) + ' 项' : '');
}
</script>
<template>
  <ListTable
    :columns="columns"
    :data-source="rows"
    :scroll="{ x: 1494 }"
    :pagination="paginate ? tablePagination() : false"
    ><template #bodyCell="{ column, record }"
      ><button
        v-if="column.key === 'name'"
        type="button"
        class="link-button record-link"
        :title="record.name"
        :disabled="disabled"
        @click="emit('inspect', record)"
      >
        {{ record.name }}
      </button>
      <template v-else-if="column.key === 'kind'">{{ watchlistKinds[record.definition.kind] }}</template>
      <template v-else-if="column.key === 'match'">{{ watchlistMatchTypes[record.definition.match_type] }}</template>
      <span v-else-if="column.key === 'values'" class="technical" :title="matchValues(record)">{{
        matchValues(record)
      }}</span><template v-else-if="column.key === 'scope'">{{ record.definition.sensors.length }} 个指定探针</template
      ><template v-else-if="column.key === 'start'">{{ formatTime(record.definition.valid_from) }}</template>
      <template v-else-if="column.key === 'end'">{{ formatTime(record.definition.valid_until) }}</template>
      <StatusTag v-else-if="column.key === 'state'" v-bind="stateBadge(record)" />
      <div v-else-if="column.key === 'actions'" class="table-row-actions">
        <a-button type="link" size="small" :disabled="disabled" @click="emit('inspect', record)">查看</a-button
        ><a-button v-if="canEdit" type="link" size="small" :disabled="disabled" @click="emit('edit', record)"
          >编辑</a-button
        ><ADropdown v-if="canEdit" :trigger="['click']" :disabled="disabled">
          <a-button type="link" size="small" :disabled="disabled" aria-haspopup="menu">更多</a-button>
          <template #overlay>
            <AMenu :selectable="false">
              <AMenuItem key="preview" :disabled="disabled" @click="emit('preview', record)">范围核验</AMenuItem>
              <AMenuItem key="state" :disabled="disabled" @click="emit('state', record)">{{
                record.active ? '停用' : '启用'
              }}</AMenuItem>
            </AMenu>
          </template>
        </ADropdown>
      </div></template
    ></ListTable
  >
</template>
