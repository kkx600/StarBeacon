<script setup lang="ts">
import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {pageById} from '../data/catalog'
import {workspaceForPage} from '../data/navigation'
import {usePreview} from '../composables/usePreview'
import ReplayPreview from '../components/ReplayPreview.vue'
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
const page=computed(()=>pageById.get(String(route.params.id)))
const workspace=computed(()=>workspaceForPage.get(String(route.params.id)))
const special={overview:OverviewView,search:SearchView,chat:ChatView,'rule-studio':RuleStudioView,playbook:PlaybookView,retention:RetentionView,topology:TopologyView,screen:ScreenView}
</script>
<template>
  <div v-if="page" class="page-surface" :data-page-id="page.id" :data-page-state="state"><nav v-if="workspace&&workspace.pages.length>1" class="workspace-views" :aria-label="`${workspace.title}功能`"><a-tabs :active-key="page.id" @change="(id:string|number)=>router.push(`/page/${id}`)"><a-tab-pane v-for="id in workspace.pages" :key="id" :tab="pageById.get(id)?.title"/></a-tabs></nav><ReplayPreview v-if="['rule-samples','rule-tests'].includes(page.id)" :tasks="page.id==='rule-tests'" :state="state" @state="setState"/><component v-else-if="page.kind!=='table'" :is="special[page.kind]" :key="page.id" :page="page" :state="state" @state="setState"/><TableWorkspace v-else :key="`table-${page.id}`" :page="page" :state="state" @state="setState"><template #before><FeatureContext v-if="state!=='empty'&&state!=='error'&&state!=='loading'" :page="page"/></template></TableWorkspace></div>
  <a-result v-else status="404" title="页面不存在" sub-title="请从页面目录选择可访问的功能。"><template #extra><router-link to="/catalog"><a-button type="primary">页面目录</a-button></router-link></template></a-result>
</template>
