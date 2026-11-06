import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
// 页签取自路由元数据并切换到对应规范路径，保留业务查询与定位标记，使刷新、复制链接与浏览器前进后退保持同一工作视图。
export function useWorkspaceView(keys: string[], fallback = keys[0]!) {
  const route=useRoute(),router=useRouter()
  const view=computed(()=>typeof route.meta.workspaceView==='string'&&keys.includes(route.meta.workspaceView)?route.meta.workspaceView:fallback)
  const change=(key:string)=>{const path=(route.meta.viewPaths as Record<string,string>|undefined)?.[key];return path?router.push({path,query:route.query,hash:route.hash}):undefined}
  return {view,change}
}
