<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { pageById } from '../data/catalog';
import CorrelationPreview from '../components/CorrelationPreview.vue';
import WatchlistsPreview from '../components/WatchlistsPreview.vue';
import MCPAccessPreview from '../components/MCPAccessPreview.vue';
import SyslogPreview from '../components/SyslogPreview.vue';
import ResponseActionsPreview from '../components/ResponseActionsPreview.vue';
import ResponseDevicesPreview from '../components/ResponseDevicesPreview.vue';
import { workspaceForPage, pageIdForRoute, prototypePath, nestedPages } from '../data/navigation';
import { usePreview } from '../composables/usePreview';
import DiscoveryPreview from '../components/DiscoveryPreview.vue';
import QualityEventsPreview from '../components/QualityEventsPreview.vue';
import NotificationsPreview from '../components/NotificationsPreview.vue';
import IncidentsPreview from '../components/IncidentsPreview.vue';
import RuleSyncPreview from '../components/RuleSyncPreview.vue';
import RuleRolloutPreview from '../components/RuleRolloutPreview.vue';
import ProbePKIPreview from '../components/ProbePKIPreview.vue';
import ReplayPreview from '../components/ReplayPreview.vue';
import ApplicationRulesPreview from '../components/ApplicationRulesPreview.vue';
import ProtocolCapabilitiesPreview from '../components/ProtocolCapabilitiesPreview.vue';
import TableWorkspace from '../components/TableWorkspace.vue';
import FeatureContext from '../components/FeatureContext.vue';
import OverviewView from './OverviewView.vue';
import SearchView from './SearchView.vue';
import ChatView from './ChatView.vue';
import RuleStudioView from './RuleStudioView.vue';
import PlaybookView from './PlaybookView.vue';
import RetentionView from './RetentionView.vue';
import TopologyView from './TopologyView.vue';
import ScreenView from './ScreenView.vue';
import AiOpsView from './AiOpsView.vue';
import PluginsView from './PluginsView.vue';
import BypassView from './BypassView.vue';
import FullTrafficView from './FullTrafficView.vue';
import SystemSettingsView from './SystemSettingsView.vue';
const route = useRoute();
const router = useRouter();
const { state, setState } = usePreview();
const page = computed(() => pageById.get(pageIdForRoute(route)));
const workspace = computed(() => workspaceForPage.get(pageIdForRoute(route)));
const parentPage = computed(() => nestedPages[page.value?.id ?? ''] ?? page.value?.id);
const nestedViews = computed(() =>
  [
    parentPage.value,
    ...Object.entries(nestedPages)
      .filter(([, parent]) => parent === parentPage.value)
      .map(([child]) => child),
  ].filter((id): id is string => !!id),
);
// 探针工作区的「质量事件」页签进入流量采集下的规范质量事件页面。
function openWorkspacePage(id: string | number) {
  void router.push(
    id === 'quality-events'
      ? { path: prototypePath('capture-quality'), query: { state: 'data' } }
      : prototypePath(String(id)),
  );
}
const special = {
  overview: OverviewView,
  search: SearchView,
  chat: ChatView,
  'rule-studio': RuleStudioView,
  playbook: PlaybookView,
  retention: RetentionView,
  topology: TopologyView,
  screen: ScreenView,
  'ai-ops': AiOpsView,
  plugins: PluginsView,
  bypass: BypassView,
  'full-traffic': FullTrafficView,
};
</script>
<template>
  <div v-if="page" class="page-surface" :data-page-id="page.id" :data-page-state="state">
    <nav v-if="workspace && workspace.pages.length > 1" class="workspace-views" :aria-label="`${workspace.title}功能`">
      <a-tabs :active-key="parentPage" @change="openWorkspacePage"
        ><a-tab-pane v-for="id in workspace.pages" :key="id" :tab="pageById.get(id)?.title" /><a-tab-pane
          v-if="workspace.id === 'sensors'"
          key="quality-events"
          tab="质量事件"
      /></a-tabs>
    </nav>
    <nav v-if="nestedViews.length > 1" class="workspace-views" aria-label="三级功能">
      <a-tabs :active-key="page.id" @change="(id: string | number) => router.push(prototypePath(String(id)))"
        ><a-tab-pane v-for="id in nestedViews" :key="id" :tab="pageById.get(id)?.title"
      /></a-tabs>
    </nav>
    <WatchlistsPreview v-if="page.id === 'watchlists'" :state="state" @state="setState" /><CorrelationPreview
      v-else-if="['correlation', 'correlation-backtest'].includes(page.id)"
      :backtest="page.id === 'correlation-backtest'"
      :state="state"
      @state="setState"
    /><SyslogPreview
      v-else-if="['syslog-input', 'logs'].includes(page.id)"
      :logs="page.id === 'logs'"
      :state="state"
      @state="setState"
    /><ResponseDevicesPreview
      v-else-if="page.id === 'devices'"
      :state="state"
      @state="setState"
    /><ResponseActionsPreview v-else-if="page.id === 'actions'" :state="state" @state="setState" /><SystemSettingsView
      v-else-if="page.id === 'system-settings'"
      :page="page"
      :state="state"
      @state="setState"
    /><DiscoveryPreview v-else-if="page.id === 'discovery'" :state="state" @state="setState" /><QualityEventsPreview
      v-else-if="page.id === 'capture-quality'"
      :state="state"
      @state="setState"
    /><NotificationsPreview
      v-else-if="['channels', 'syslog-output', 'delivery-logs'].includes(page.id)"
      :page="page.id"
      :state="state"
      @state="setState"
    /><IncidentsPreview v-else-if="page.id === 'incidents'" :state="state" @state="setState" /><ProbePKIPreview
      v-else-if="page.id === 'probe-identity'"
      :state="state"
      @state="setState"
    /><RuleRolloutPreview v-else-if="page.id === 'rule-rollouts'" :state="state" @state="setState" /><RuleSyncPreview
      v-else-if="page.id === 'rule-sync'"
      :state="state"
      @state="setState"
    /><ReplayPreview
      v-else-if="['rule-samples', 'rule-tests'].includes(page.id)"
      :tasks="page.id === 'rule-tests'"
      :state="state"
      @state="setState"
    /><ProtocolCapabilitiesPreview
      v-else-if="page.id === 'protocols'"
      :state="state"
      @state="setState"
    /><ApplicationRulesPreview v-else-if="page.id === 'application-rules'" :state="state" @state="setState" /><component
      v-else-if="page.kind !== 'table'"
      :is="special[page.kind]"
      :key="page.id"
      :page="page"
      :state="state"
      @state="setState"
    /><TableWorkspace v-else :key="`table-${page.id}`" :page="page" :state="state" @state="setState"
      ><template #before
        ><MCPAccessPreview v-if="page.id === 'mcp'" /><router-link
          v-if="page.id === 'assets'"
          :to="{ path: prototypePath('discovery'), query: { state: 'data' } }"
          class="asset-discovery-link"
          ><a-button>被动发现</a-button></router-link
        ><FeatureContext
          v-if="state !== 'empty' && state !== 'error' && state !== 'loading' && page.family !== 'decision-evaluation'"
          :page="page" /></template
    ></TableWorkspace>
  </div>
  <a-result v-else status="404" title="页面不存在" sub-title="请从页面目录选择可访问的功能。"
    ><template #extra
      ><router-link to="/catalog"><a-button type="primary">页面目录</a-button></router-link></template
    ></a-result
  >
</template>
