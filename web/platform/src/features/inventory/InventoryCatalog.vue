<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('资产管理');
import { computed, shallowRef, watch } from 'vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import { session } from '../../session';
import InventoryTable from './InventoryTable.vue';
import InventoryForm from './InventoryForm.vue';
import InventoryDetail from './InventoryDetail.vue';
import {
  inventoryNames,
  inventoryObjectNames,
  type InventoryKind,
  type InventoryRecord,
  type InventoryData,
} from './inventory';
import { useInventory } from './useInventory';
const props = defineProps<{ kind: InventoryKind }>();
const kind = computed(() => props.kind),
  editable = computed(() => session.current.value?.role === 'admin');
const {
  result,
  pending,
  error,
  saving,
  saveError,
  save,
  cursors,
  pageSize,
  changePageSize,
  next,
  previous,
  search,
  refresh,
  clearSaveError,
} = useInventory(kind);
const keyword = shallowRef(''),
  editing = shallowRef<InventoryRecord | null>(null),
  editorOpen = shallowRef(false),
  selected = shallowRef<InventoryRecord | null>(null);
watch(kind, () => {
  editorOpen.value = false;
  editing.value = null;
  selected.value = null;
  keyword.value = '';
});
function openEditor(record: InventoryRecord | null) {
  editing.value = record;
  clearSaveError();
  editorOpen.value = true;
}
async function saveRecord(data: InventoryData, id: string) {
  const record = editing.value ?? { id, kind: kind.value, revision: 0, data, created_at: '', updated_at: '' };
  if (await save(data, record)) {
    editorOpen.value = false;
    editing.value = null;
  }
}
</script>
<template>
  <PageHeader :title="pageTitle" description="维护资产通信地址、责任范围与网络域，按历史修订核对调查时的配置。">
    <a-button :loading="pending" @click="refresh">刷新</a-button>
    <a-button v-if="editable" type="primary" :disabled="saving" @click="openEditor(null)"
      >创建{{ inventoryObjectNames[kind] }}</a-button
    >
  </PageHeader>
  <a-form :model="{ keyword }" layout="horizontal" @finish="search(keyword)">
    <ListFilters :columns="2" label="资产目录筛选">
      <a-form-item label="名称" html-for="inventory-keyword">
        <a-input id="inventory-keyword" v-model:value="keyword" :maxlength="128" placeholder="按名称查找" allow-clear />
      </a-form-item>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="pending">查询</a-button>
        <a-button
          :disabled="pending"
          @click="
            keyword = '';
            search('');
          "
          >重置</a-button
        >
      </template>
    </ListFilters>
  </a-form>
  <section class="panel">
    <div class="panel-header">
      <h2>{{ inventoryNames[kind] }}</h2>
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="result.items.length === 0"
      :description="`当前条件下没有${inventoryNames[kind]}。`"
      @retry="refresh"
      ><InventoryTable
        :kind="kind"
        :records="result.items"
        :editable="editable"
        @edit="openEditor"
        @view="selected = $event"
    /></StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="error ? undefined : result.items.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!result.next_cursor"
      :disabled="pending"
      @previous="previous"
      @next="next"
      @update:page-size="changePageSize"
    />
  </section>
  <InventoryForm
    v-if="editorOpen"
    :kind="kind"
    :record="editing"
    :pending="saving"
    :error="saveError"
    @save="saveRecord"
    @close="editorOpen = false"
  />
  <InventoryDetail :record="selected" @close="selected = null" />
</template>
