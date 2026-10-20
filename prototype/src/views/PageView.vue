<script setup lang="ts">
import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {pageById} from '../data/catalog'
import SettingsWorkspace from '../../../web/platform/src/features/settings/SettingsWorkspace.vue'
import ResponseActionsPreview from '../components/ResponseActionsPreview.vue'
import {workspaceForPage,pageIdForRoute,prototypePath,nestedPages} from '../data/navigation'
import {usePreview} from '../composables/usePreview'
import DiscoveryPreview from '../components/DiscoveryPreview.vue'
import QualityEventsPreview from '../components/QualityEventsPreview.vue'
import NotificationsPreview from '../components/NotificationsPreview.vue'
import IncidentsPreview from '../components/IncidentsPreview.vue'
import RuleSyncPreview from '../components/RuleSyncPreview.vue'
import RuleRolloutPreview from '../components/RuleRolloutPreview.vue'
import ProbePKIPreview from '../components/ProbePKIPreview.vue'
import ReplayPreview from '../components/ReplayPreview.vue'
import ApplicationRulesPreview from '../components/ApplicationRulesPreview.vue'
import ProtocolCapabilitiesPreview from '../components/ProtocolCapabilitiesPreview.vue'
import TableWorkspace from '../components/TableWorkspace.vue'
import FeatureContext from '../components/FeatureContext.vue'
import OverviewView from './OverviewView.vue'
import SearchView from './SearchView.vue'
import ChatView from './ChatView.vue'
import RuleStudioView from './RuleStudioView.vue'
import PlaybookView from './PlaybookView.vue'
import RetentionView from './RetentionView.vue'
import TopologyView from './TopologyView.vue'
import ScreenView from './ScreenView.vue'
const route=useRoute();const router=useRouter();const {state,setState}=usePreview()
const page=computed(()=>pageById.get(pageIdForRoute(route)))
const workspace=computed(()=>workspaceForPage.get(pageIdForRoute(route)))
const parentPage=computed(()=>nestedPages[page.value?.id??'']??page.value?.id)
const nestedViews=computed(()=>[parentPage.value,...Object.entries(nestedPages).filter(([,parent])=>parent===parentPage.value).map(([child])=>child)].filter((id):id is string=>!!id))
const activeNested=computed(()=>page.value?.id==='assets'&&route.query.view==='discovery'?'discovery':page.value?.id==='rule-sync'&&route.query.mode==='rollouts'?'rule-rollouts':page.value?.id)
const special={overview:OverviewView,search:SearchView,chat:ChatView,'rule-studio':RuleStudioView,playbook:PlaybookView,retention:RetentionView,topology:TopologyView,screen:ScreenView}
</script>
<template>
  <div v-if="page" class="page-surface" :data-page-id="page.id" :data-page-state="state"><nav v-if="workspace&&workspace.pages.length>1" class="workspace-views" :aria-label="`${workspace.title}功能`"><a-tabs :active-key="page.id==='sensors'&&route.query.view==='quality'?'quality-events':parentPage" @change="(id:string|number)=>id==='quality-events'?router.push({path:'/page/sensors',query:{view:'quality',state:'data'}}):router.push(prototypePath(String(id)))"><a-tab-pane v-for="id in workspace.pages" :key="id" :tab="pageById.get(id)?.title"/><a-tab-pane v-if="workspace.id==='sensors'" key="quality-events" tab="质量事件"/></a-tabs></nav><nav v-if="nestedViews.length>1" class="workspace-views" aria-label="三级功能"><a-tabs :active-key="activeNested" @change="(id:string|number)=>router.push(prototypePath(String(id)))"><a-tab-pane v-for="id in nestedViews" :key="id" :tab="pageById.get(id)?.title"/></a-tabs></nav><ResponseActionsPreview v-if="page.id==='actions'" :state="state" @state="setState"/><SettingsWorkspace v-else-if="page.id==='system-settings'"/><DiscoveryPreview v-else-if="page.id==='discovery'||page.id==='assets'&&route.query.view==='discovery'" :state="state" @state="setState"/><QualityEventsPreview v-else-if="(page.id==='capture-quality'||page.id==='sensors'&&route.query.view==='quality')" :state="state" @state="setState"/><NotificationsPreview v-else-if="['channels','syslog-output','delivery-logs'].includes(page.id)" :page="page.id" :state="state" @state="setState"/><IncidentsPreview v-else-if="page.id==='incidents'" :state="state" @state="setState"/><ProbePKIPreview v-else-if="page.id==='probe-identity'" :state="state" @state="setState"/><RuleRolloutPreview v-else-if="page.id==='rule-rollouts'||page.id==='rule-sync'&&route.query.mode==='rollouts'" :state="state" @state="setState"/><RuleSyncPreview v-else-if="page.id==='rule-sync'" :state="state" @state="setState"/><ReplayPreview v-else-if="['rule-samples','rule-tests'].includes(page.id)" :tasks="page.id==='rule-tests'" :state="state" @state="setState"/><ProtocolCapabilitiesPreview v-else-if="page.id==='protocols'" :state="state" @state="setState"/><ApplicationRulesPreview v-else-if="page.id==='application-rules'" :state="state" @state="setState"/><component v-else-if="page.kind!=='table'" :is="special[page.kind]" :key="page.id" :page="page" :state="state" @state="setState"/><TableWorkspace v-else :key="`table-${page.id}`" :page="page" :state="state" @state="setState"><template #before><router-link v-if="page.id==='assets'" :to="{path:route.path,query:{view:'discovery',state:'data'}}" class="asset-discovery-link"><a-button>被动发现</a-button></router-link><FeatureContext v-if="state!=='empty'&&state!=='error'&&state!=='loading'&&page.family!=='decision-evaluation'" :page="page"/></template></TableWorkspace></div>
  <a-result v-else status="404" title="页面不存在" sub-title="请从页面目录选择可访问的功能。"><template #extra><router-link to="/catalog"><a-button type="primary">页面目录</a-button></router-link></template></a-result>
</template>
