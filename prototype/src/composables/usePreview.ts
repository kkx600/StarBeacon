import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { states } from '../data/catalog'
import type { PreviewState } from '../models'

export function usePreview() {
  const route=useRoute();const router=useRouter()
  const state=computed<PreviewState>(() => states.some(s=>s.value===route.query.state)?route.query.state as PreviewState:'data')
  function setState(value: PreviewState) { void router.replace({query:{...route.query,state:value}}) }
  function closeOverlay() {if(state.value==='detail'||state.value==='action')setState('data')}
  return {state,setState,closeOverlay}
}
