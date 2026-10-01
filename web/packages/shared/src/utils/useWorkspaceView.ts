import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
// 页签写入查询参数，使刷新、复制链接与浏览器前进后退保持同一工作视图。
export function useWorkspaceView(keys: string[], fallback = keys[0]!) {
  const route=useRoute(),router=useRouter()
  const view=computed(()=>typeof route.query.view==='string'&&keys.includes(route.query.view)?route.query.view:fallback)
  const change=(key:string)=>router.push({path:route.path,query:{...route.query,view:key===fallback?undefined:key},hash:route.hash})
  return {view,change}
}
