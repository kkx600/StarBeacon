import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
// 页签写入查询参数，使刷新、复制链接与浏览器前进后退保持同一工作视图。
export function useWorkspaceView(keys: string[], fallback = keys[0]!) {
  const route=useRoute(),router=useRouter()
  const view=computed(()=>typeof route.meta.workspaceView==='string'&&keys.includes(route.meta.workspaceView)?route.meta.workspaceView:typeof route.query.view==='string'&&keys.includes(route.query.view)?route.query.view:fallback)
  const change=(key:string)=>{
    const paths=route.meta.viewPaths as Record<string,string>|undefined
    const {view:ignoredView,mode:ignoredMode,...query}=route.query
    return paths?.[key]?router.push({path:paths[key],query,hash:route.hash}):router.push({path:route.path,query:{...route.query,view:key===fallback?undefined:key},hash:route.hash})
  }
  return {view,change}
}
