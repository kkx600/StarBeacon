<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('通知中心');
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { computed, shallowRef, watch } from 'vue';
import { Select } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import { useWorkspaceView } from '@starbeacon/shared/utils/useWorkspaceView.ts';
import { useNotifications } from './useNotifications';
import { deliveryNames, type Channel, type ChannelChange, type Delivery } from './notifications';
import ChannelTable from './ChannelTable.vue';
import ChannelForm from './ChannelForm.vue';
import DeliveryTable from './DeliveryTable.vue';
import DeliveryDetail from './DeliveryDetail.vue';
const message = useFeedback();
const { view, change } = useWorkspaceView(['channels', 'deliveries']);
const state = useNotifications(view);
const {
  channels,
  deliveries,
  available,
  development,
  pending,
  error,
  busy,
  actionError,
  cursors,
  nextCursor,
  pageSize,
} = state;
const editing = shallowRef<Channel | null>(null),
  editorOpen = shallowRef(false),
  selectedID = shallowRef(''),
  filter = shallowRef('');
const selected = computed(() => deliveries.value.find(item => item.id === selectedID.value) ?? null);
watch(view, () => {
  editorOpen.value = false;
  editing.value = null;
  selectedID.value = '';
  filter.value = '';
});
function edit(record: Channel | null) {
  state.clearActionError();
  editing.value = record;
  editorOpen.value = true;
}
async function save(change: ChannelChange) {
  if (await state.save(change)) {
    editorOpen.value = false;
    message.success('通知渠道已保存');
  }
}
async function test(record: Channel) {
  if (await state.test(record)) {
    message.success('测试投递已受理，请查看推送日志');
    change('deliveries');
  }
}
async function retry(record: Delivery) {
  if (await state.retry(record)) message.success('人工重试已受理');
}
function move(direction: 'previous' | 'next') {
  selectedID.value = '';
  state[direction]();
}
function resize(size: number) {
  selectedID.value = '';
  state.changePageSize(size);
}
function search() {
  selectedID.value = '';
  state.search(filter.value);
}
function reset() {
  filter.value = '';
  search();
}
</script>
<template>
  <PageHeader :title="pageTitle" description="配置告警通知和日志转发渠道，核对每次投递的处理状态与渠道回执。">
    <a-button :loading="pending" @click="state.refresh">刷新</a-button>
    <a-button
      v-if="view === 'channels'"
      type="primary"
      :disabled="!available || busy || channels.length >= 50"
      @click="edit(null)"
      >创建渠道</a-button
    >
  </PageHeader>
  <WorkspaceTabs
    :active="view"
    :items="[
      { key: 'channels', label: '通知渠道' },
      { key: 'deliveries', label: '推送日志' },
    ]"
    label="通知中心功能"
    @change="change"
  />
  <a-alert v-if="actionError && !editorOpen" type="error" :message="actionError" show-icon class="section-gap" />
  <a-alert
    v-if="view === 'channels' && !pending && !available && !error"
    type="info"
    message="通知服务未启用。"
    show-icon
    class="section-gap"
  />
  <form v-if="view === 'deliveries'" @submit.prevent="search">
    <ListFilters label="推送日志筛选" :columns="2">
      <div class="filter-field">
        <label for="delivery-state">投递状态</label>
        <Select
          id="delivery-state"
          v-model:value="filter"
          aria-label="投递状态"
          :options="[
            { value: '', label: '全部状态' },
            ...Object.entries(deliveryNames).map(([value, label]) => ({ value, label })),
          ]"
        />
      </div>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="pending">查询</a-button>
        <a-button :disabled="pending" @click="reset">重置</a-button>
      </template>
    </ListFilters>
  </form>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>{{ view === 'channels' ? '通知渠道' : '推送日志' }}</h2>
      <MetricBar
        v-if="view === 'channels' && !pending && !error"
        embedded
        :items="[{ label: '已配置渠道', value: channels.length, suffix: '/ 50' }]"
      />
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="view === 'channels' ? channels.length === 0 : deliveries.length === 0"
      :description="view === 'channels' ? '暂无通知渠道，可创建渠道并发送测试消息。' : '当前条件下没有推送日志。'"
      @retry="state.refresh"
      ><ChannelTable
        v-if="view === 'channels'"
        :items="channels"
        :busy="busy"
        :available="available"
        @edit="edit"
        @test="test" /><DeliveryTable v-else :items="deliveries" @view="selectedID = $event.id"
    /></StatePanel>
    <ListPager
      v-if="view === 'deliveries'"
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="pending || error ? undefined : deliveries.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!nextCursor"
      :disabled="pending"
      @previous="move('previous')"
      @next="move('next')"
      @update:page-size="resize"
    />
  </section>
  <ChannelForm
    v-if="editorOpen"
    :record="editing"
    :pending="busy"
    :error="actionError"
    :development="development"
    @save="save"
    @close="editorOpen = false"
  />
  <DeliveryDetail :record="selected" :busy="busy" @close="selectedID = ''" @retry="retry" />
</template>
