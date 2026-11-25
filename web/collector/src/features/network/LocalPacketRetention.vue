<script setup lang="ts">
import { onMounted, onScopeDispose, shallowRef } from 'vue';
import PacketRetentionEditor from '@starbeacon/shared/components/PacketRetentionEditor.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import {
  sameRetentionPolicy,
  validRetentionStatus,
  validRetentionObservation,
  type PacketRetentionChange,
  type PacketRetentionStatus,
} from '@starbeacon/shared/packetRetention.ts';
import { session } from '../../session';

const status = shallowRef<PacketRetentionStatus | null>(null);
const pending = shallowRef(true);
const saving = shallowRef(false);
const error = shallowRef('');
const result = shallowRef('');
const saveError = shallowRef('');
let controller: AbortController | undefined;

async function load() {
  controller?.abort();
  const active = new AbortController();
  controller = active;
  pending.value = true;
  error.value = '';
  try {
    const value = await session.api.request<unknown>('/packet-retention', { signal: active.signal });
    if (active.signal.aborted) return;
    if (!validRetentionStatus(value)) throw new Error('留存策略回执格式无效，请重试');
    status.value = value;
  } catch (e) {
    if (!active.signal.aborted) error.value = e instanceof Error ? e.message : '留存策略读取失败';
  } finally {
    if (!active.signal.aborted) pending.value = false;
  }
}

async function save(change: PacketRetentionChange) {
  if (saving.value || pending.value || status.value?.state !== 'ready') return;
  const active = new AbortController();
  controller = active;
  saving.value = true;
  result.value = '';
  saveError.value = '';
  try {
    const value = await session.api.request<unknown>('/packet-retention', {
      method: 'PUT',
      body: change,
      signal: active.signal,
    });
    if (active.signal.aborted) return;
    if (
      !validRetentionObservation(value) ||
      value.origin !== 'local' ||
      !sameRetentionPolicy(value.policy, change.policy)
    )
      throw new Error('保存回执无法核对，请刷新留存策略');
    status.value = { ...status.value, configuration: value };
    result.value = `本机已保存修订 ${value.policy.revision}，下次封段使用新策略，并经心跳同步到平台。`;
  } catch (e) {
    if (!active.signal.aborted) saveError.value = e instanceof Error ? e.message : '留存策略保存失败';
  } finally {
    if (!active.signal.aborted) saving.value = false;
  }
}

onMounted(load);
onScopeDispose(() => controller?.abort());
</script>

<template>
  <section class="panel" aria-labelledby="local-retention-title">
    <div class="panel-header">
      <h2 id="local-retention-title">全流量留存</h2>
      <a-button :loading="pending" :disabled="saving" @click="load">刷新留存策略</a-button>
    </div>
    <StatePanel v-if="!status || error" :loading="pending" :error="error" @retry="load" />
    <div v-if="status" class="panel-body">
      <a-alert v-if="saveError" class="section-gap" type="error" :message="saveError" show-icon />
      <a-alert v-if="result" class="section-gap" type="success" :message="result" show-icon />
      <PacketRetentionEditor
        v-if="status.configuration"
        :observation="status.configuration"
        :saving="saving"
        :disabled="pending || !!error"
        @save="save"
      />
      <p v-else-if="status.state === 'unavailable'" class="muted">
        留存配置无法核对。后续封段按原样保留，请检查本地配置。
      </p>
      <p v-else class="muted">本机未启用留存策略管理。</p>
    </div>
  </section>
</template>
