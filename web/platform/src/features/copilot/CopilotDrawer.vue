<script setup lang="ts">
import { computed, onScopeDispose, shallowRef } from 'vue';
import { Alert, Button, Drawer, Input, type DrawerProps } from 'ant-design-vue';
import { SendOutlined } from '@ant-design/icons-vue';
import { RouterLink } from 'vue-router';
import {
  formatTime,
  type Alert as AlertRecord,
  type SearchRequest,
  type SearchResult,
} from '@starbeacon/shared/types.ts';
import { session } from '../../session';
import { readMetrics, type PlanMetrics } from '../decisions/automation';
import { countText, type Overview } from '../overview/overview';
import PluginGenerationDialog from '../plugins/PluginGenerationDialog.vue';
import CopilotAlertTriage from './CopilotAlertTriage.vue';
import CopilotAnalysis from './CopilotAnalysis.vue';
import type { CopilotAlert } from './context';
import { naturalAlertQuery } from './search';

const props = defineProps<{
  context: string;
  workspace: string;
  alert?: CopilotAlert;
  chatPath?: string;
  overview?: Overview;
}>();
const emit = defineEmits<{ close: [] }>();
type Mode = 'search' | 'triage' | 'draft' | 'explain' | 'analysis';
const mode = shallowRef<Mode>(props.alert && props.chatPath ? 'triage' : 'search');
const input = shallowRef('');
const rows = shallowRef<AlertRecord[]>([]);
const result = shallowRef<{ query: SearchRequest; total: number }>();
const stats = shallowRef<PlanMetrics>();
const plugin = shallowRef(false);
const busy = shallowRef(false);
const error = shallowRef('');
let controller: AbortController | undefined;
const width: DrawerProps['width'] = 'min(100vw, 440px)';
const searchLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  unknown: '未知',
};
const isOverview = computed(() => props.workspace === 'overview');
const isOps = computed(() => props.workspace === 'ai-ops');
function pick(value: Mode) {
  controller?.abort();
  busy.value = false;
  error.value = '';
  mode.value = value;
  if (value === 'explain' && isOps.value) void explain();
}
async function search() {
  if (!input.value.trim() || busy.value) return;
  controller?.abort();
  const request = new AbortController();
  controller = request;
  busy.value = true;
  error.value = '';
  result.value = undefined;
  rows.value = [];
  try {
    const query = naturalAlertQuery(input.value);
    const data = await session.api.request<SearchResult>('/alerts/search', {
      method: 'POST',
      body: query,
      signal: request.signal,
    });
    if (request.signal.aborted) return;
    if (!Array.isArray(data.items) || !Number.isSafeInteger(data.total) || data.total < 0)
      throw new Error('告警检索结果未完整返回。');
    rows.value = data.items;
    result.value = { query, total: data.total };
  } catch (cause) {
    if (!request.signal.aborted) error.value = cause instanceof Error ? cause.message : '检索失败。';
  } finally {
    if (controller === request) busy.value = false;
  }
}
async function explain() {
  controller?.abort();
  const request = new AbortController();
  controller = request;
  busy.value = true;
  error.value = '';
  stats.value = undefined;
  try {
    const data = await readMetrics(request.signal);
    if (!request.signal.aborted) stats.value = data;
  } catch (cause) {
    if (!request.signal.aborted) error.value = cause instanceof Error ? cause.message : '读取页面统计失败。';
  } finally {
    if (controller === request) busy.value = false;
  }
}
onScopeDispose(() => controller?.abort());
</script>

<template>
  <Drawer :open="true" title="AI 助手" placement="right" :width="width" :z-index="1100" @close="emit('close')">
    <div class="copilot">
      <div class="copilot-context">
        <div>
          <span class="muted">当前页面</span> <strong>{{ context }}</strong>
        </div>
        <div v-if="alert">
          <span class="muted">当前告警</span> <strong>{{ alert.title }}</strong>
        </div>
      </div>
      <div class="copilot-actions" aria-label="助手快捷操作">
        <Button size="small" :type="mode === 'search' ? 'primary' : 'default'" @click="pick('search')">检索告警</Button>
        <Button v-if="chatPath" size="small" :type="mode === 'triage' ? 'primary' : 'default'" @click="pick('triage')"
          >研判当前告警</Button
        >
        <Button size="small" :type="mode === 'explain' ? 'primary' : 'default'" @click="pick('explain')"
          >解释本页数据</Button
        >
        <Button v-if="chatPath" size="small" :type="mode === 'draft' ? 'primary' : 'default'" @click="pick('draft')"
          >生成处置编排</Button
        >
        <Button v-if="chatPath" size="small" @click="plugin = true">生成联动插件</Button>
        <Button
          v-if="chatPath"
          size="small"
          :type="mode === 'analysis' ? 'primary' : 'default'"
          @click="pick('analysis')"
          >统计问答</Button
        >
      </div>
      <RouterLink v-if="chatPath" :to="chatPath" class="copilot-long" @click="emit('close')">打开智能对话</RouterLink>
      <Alert v-if="error" show-icon type="error" :message="error" />
      <div v-if="mode === 'search'" class="copilot-section">
        <form class="copilot-search" @submit.prevent="search">
          <label for="copilot-search">用自然语言检索告警</label>
          <Input.TextArea
            id="copilot-search"
            v-model:value="input"
            :rows="2"
            aria-label="检索描述"
            placeholder="例如最近 24 小时的高危告警"
            :maxlength="256"
          />
          <Button type="primary" html-type="submit" :loading="busy" :disabled="!input.trim()">
            <SendOutlined aria-hidden="true" />检索
          </Button>
        </form>
        <div v-if="result" class="copilot-result" aria-live="polite">
          <h3>{{ result.total }} 条匹配告警</h3>
          <p class="muted">{{ formatTime(result.query.start) }} 至 {{ formatTime(result.query.end) }}</p>
          <p v-if="result.query.severity || result.query.keyword" class="muted">
            {{ [searchLabels[result.query.severity], result.query.keyword].filter(Boolean).join(' · ') }}
          </p>
          <ul v-if="rows.length">
            <li v-for="row in rows" :key="row.event_id">
              <strong>{{ row.rule.name || '未命名规则' }}</strong>
              <small>{{ searchLabels[row.severity] }} · {{ formatTime(row['@timestamp']) }}</small>
            </li>
          </ul>
          <p v-if="result.total > rows.length" class="muted">显示最近 {{ rows.length }} 条。</p>
        </div>
      </div>
      <template v-else-if="mode === 'triage'">
        <CopilotAlertTriage v-if="alert && chatPath" :key="alert.eventID + '/' + alert.digest" :alert="alert" />
        <div v-else class="copilot-section">
          <p>在告警详情打开助手，带入需要研判的告警。</p>
          <RouterLink to="/alerts/list" @click="emit('close')">打开告警列表</RouterLink>
        </div>
      </template>
      <div v-else-if="mode === 'explain'" class="copilot-section" aria-live="polite">
        <p v-if="busy" class="muted">正在读取页面数据</p>
        <template v-else-if="stats">
          <h3>值守指标</h3>
          <p>待确认 {{ stats.pending }} 项。按 {{ stats.timezone }} 自然日，已完成研判 {{ stats.triage_count }} 条。</p>
          <p>设备收到并回读 {{ stats.executed }} 次，自动处置 {{ stats.automatic }} 次。流水单独记录解除回读。</p>
        </template>
        <template v-else-if="isOverview && overview">
          <h3>态势总览</h3>
          <p>
            页面所选时段已索引告警 {{ countText(overview.events.total) }} 条。探针在线和资产数量按统计生成时间读取。
          </p>
          <p>{{ formatTime(overview.window.start) }} 至 {{ formatTime(overview.window.end) }}</p>
        </template>
        <p v-else-if="isOverview">当前页面的统计尚未加载。</p>
        <template v-else-if="alert">
          <h3>告警研判依据</h3>
          <p>当前告警由检测规则命中。查看详情可核对通信元数据、规则修订和证据范围。</p>
        </template>
        <CopilotAnalysis
          v-else-if="chatPath && !error"
          :draft="false"
          :context="context"
          :question="'解释与「' + context + '」相关的告警统计口径和当前可核对的数据。'"
        />
        <p v-else-if="!error">通过本页列表和当前筛选条件核对数据。告警指标可在态势总览查看。</p>
        <Button v-if="error && isOps" size="small" @click="explain">重试</Button>
      </div>
      <CopilotAnalysis v-else-if="chatPath" :key="mode" :draft="mode === 'draft'" :context="context" />
    </div>
    <PluginGenerationDialog v-if="plugin && chatPath" draft-only @close="plugin = false" />
  </Drawer>
</template>

<style scoped>
.copilot {
  display: grid;
  align-content: start;
  gap: var(--field-gap);
  min-height: 100%;
}
.copilot-context {
  display: grid;
  gap: var(--label-gap);
  padding-block: var(--related-gap);
  border-block-end: 1px solid var(--line);
  overflow-wrap: anywhere;
}
.copilot-context span {
  margin-inline-end: var(--related-gap);
}
.copilot-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--related-gap);
}
.copilot-long {
  justify-self: start;
}
.copilot-section,
.copilot-search,
.copilot-result,
.copilot-result li {
  display: grid;
  gap: var(--related-gap);
}
.copilot-search :deep(.ant-btn) {
  justify-self: end;
}
.copilot-result {
  padding-top: var(--field-gap);
  border-top: 1px solid var(--line);
}
.copilot-result ul {
  padding: 0;
  list-style: none;
}
.copilot-result li + li {
  margin-top: var(--related-gap);
}
.copilot-result li {
  gap: var(--label-gap);
  padding-bottom: var(--related-gap);
  border-bottom: 1px solid var(--line);
  overflow-wrap: anywhere;
}
.copilot-result small {
  color: var(--muted);
}
.copilot-section :is(h3, p, ul) {
  margin: 0;
}
</style>
