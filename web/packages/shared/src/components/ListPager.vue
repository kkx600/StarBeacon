<script setup lang="ts">
import {computed} from 'vue'
import {Button as AButton, Pagination as APagination, Select as ASelect} from 'ant-design-vue'
import {defaultPageSize, pageSizeOptions, totalText} from '../pagination'

// 列表统一分页条。页码分页和游标分页（只能前后翻页）共用同一位置、同一组每页条数。
const props = withDefaults(
  defineProps<{
    mode?: 'page' | 'cursor'
    page: number
    pageSize?: number
    // 页码分页必填；游标分页在接口给出总数时填写。
    total?: number
    // 游标分页：本页实际条数。
    count?: number
    hasPrevious?: boolean
    hasNext?: boolean
    disabled?: boolean
  }>(),
  {mode: 'page', pageSize: defaultPageSize, total: undefined, count: undefined, hasPrevious: false, hasNext: false, disabled: false},
)
const emit = defineEmits<{
  'update:page': [page: number]
  'update:pageSize': [pageSize: number]
  previous: []
  next: []
}>()

const sizeOptions = pageSizeOptions.map(value => ({value, label: `${value} 条/页`}))
const summary = computed(() => {
  const parts = [`第 ${props.page} 页`]
  if (props.count !== undefined) parts.push(`本页 ${props.count} 条`)
  if (props.total !== undefined) parts.push(totalText(props.total))
  return parts.join(' · ')
})

function changePage(page: number, pageSize: number) {
  if (pageSize !== props.pageSize) {
    emit('update:pageSize', pageSize)
    emit('update:page', 1)
    return
  }
  emit('update:page', page)
}
function changeSize(value: unknown) {
  emit('update:pageSize', Number(value))
  emit('update:page', 1)
}
</script>

<template>
  <div class="list-pager" :class="{'list-pager-cursor': mode === 'cursor'}">
    <APagination
      v-if="mode === 'page'"
      :current="page"
      :page-size="pageSize"
      :total="total ?? 0"
      :page-size-options="pageSizeOptions.map(String)"
      :show-total="totalText"
      :disabled="disabled"
      show-size-changer
      size="small"
      @change="changePage"
    />
    <template v-else>
      <span class="list-pager-summary">{{ summary }}</span>
      <AButton size="small" :disabled="disabled || !hasPrevious" @click="emit('previous')">上一页</AButton>
      <AButton size="small" :disabled="disabled || !hasNext" @click="emit('next')">下一页</AButton>
      <ASelect
        class="list-pager-size"
        size="small"
        aria-label="每页条数"
        :value="pageSize"
        :options="sizeOptions"
        :disabled="disabled"
        @change="changeSize"
      />
    </template>
  </div>
</template>

<style scoped>
.list-pager {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: var(--related-gap);
  padding: var(--related-gap) var(--panel-inset);
  border-top: 1px solid var(--line);
}
.list-pager-summary {
  color: var(--muted);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.list-pager-size {
  min-width: 104px;
}
</style>
