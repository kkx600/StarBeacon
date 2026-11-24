<script setup lang="ts" generic="Row extends object, Column extends TableColumnType<Row>">
import { Table as ATable, type TableColumnType, type TableProps } from 'ant-design-vue';

const props = withDefaults(
  defineProps<{
    columns: Column[];
    dataSource: Row[];
    rowKey?: TableProps<Row>['rowKey'];
    rowSelection?: TableProps<Row>['rowSelection'];
    scroll?: TableProps<Row>['scroll'];
    pagination?: TableProps<Row>['pagination'];
  }>(),
  { rowKey: 'id', pagination: false },
);
// 组件库的插槽类型未携带传入表格的行与列类型。
type TableCell = { column: Column; record: Row; text: unknown; index: number };
defineSlots<{ bodyCell?: (cell: TableCell) => unknown }>();
</script>

<template>
  <ATable v-bind="props" size="small" class="list-table">
    <template v-if="$slots.bodyCell" #bodyCell="cell">
      <slot name="bodyCell" v-bind="cell as unknown as TableCell" />
    </template>
  </ATable>
</template>
