import { createRouter, createWebHistory, type RouterHistory, type RouteRecordRaw } from 'vue-router'
import {migrateLegacyHash} from '@starbeacon/shared/utils/history.ts'
import {collectorCanonicalDestination,collectorDefaultDestination,collectorLegacyDestination,collectorMeta} from './navigation'
import { session } from './session'
migrateLegacyHash(import.meta.env.BASE_URL)

const workspace=()=>import('./views/CollectorView.vue')
export function collectorRoutes(): RouteRecordRaw[] {
  return [
    {path:'/',redirect:to=>collectorDefaultDestination(to,'/overview/status')},
    {path:'/login',component:()=>import('./views/LoginView.vue')},
    {path:'/access-denied',component:()=>import('./views/AccessDeniedView.vue'),meta:{title:'访问受限'}},
    {path:'/overview',redirect:to=>collectorDefaultDestination(to,'/overview/status'),children:[
      {path:'status',component:workspace,meta:collectorMeta('overview')},
    ]},
    {path:'/network',redirect:collectorLegacyDestination,children:[
      {path:'interfaces',component:workspace,meta:collectorMeta('interfaces')},
      {path:'capture',component:workspace,meta:collectorMeta('capture')},
      {path:'archives',component:workspace,meta:collectorMeta('archives')},
      {path:'syslog',component:workspace,meta:collectorMeta('syslog')},
    ]},
    {path:'/connection',redirect:to=>collectorDefaultDestination(to,'/connection/identity'),children:[
      {path:'identity',component:workspace,meta:collectorMeta('identity')},
    ]},
    {path:'/rules',redirect:to=>collectorDefaultDestination(to,'/rules/samples'),children:[
      {path:'samples',component:workspace,meta:collectorMeta('samples')},
      {path:'tasks',component:workspace,meta:collectorMeta('tasks')},
    ]},
    {path:'/response',redirect:to=>collectorDefaultDestination(to,'/response/devices'),children:[
      {path:'devices',component:workspace,meta:collectorMeta('responses')},
    ]},
    {path:'/:pathMatch(.*)*',component:()=>import('@starbeacon/shared/components/NotFound.vue'),props:{home:'/overview/status'},meta:{title:'页面不存在'}},
  ]
}

export function createCollectorRouter(history: RouterHistory = createWebHistory(import.meta.env.BASE_URL)) {
  const router=createRouter({history,scrollBehavior:()=>({top:0}),routes:collectorRoutes()})
  router.beforeEach(async to=>{
    if(to.path==='/login')return
    const canonical=collectorCanonicalDestination(to)
    if(canonical)return canonical
    try{await session.restore()}catch{return {path:'/login',query:{redirect:to.fullPath}}}
    if(!session.current.value)return {path:'/login',query:{redirect:to.fullPath}}
    if(to.meta.admin&&session.current.value.role!=='admin')return {path:'/access-denied',query:{redirect:to.fullPath}}
  })
  return router
}

export const router=createCollectorRouter()
