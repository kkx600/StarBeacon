import manifest from '@starbeacon/shared/navigation.json' with {type:'json'}
import type {RouteRecordRaw,RouteLocationNormalized,RouteLocationRaw} from 'vue-router'
import {navigationGroups,navigationWorkspaces,platformScreens,workspacePath,type PlatformScreen} from '@starbeacon/shared/navigation.ts'

const components:Record<string,NonNullable<RouteRecordRaw['component']>>={
  overview:()=>import('./views/OverviewView.vue'),screen:()=>import('./views/OverviewView.vue'),
  sensors:()=>import('./views/SensorsView.vue'),rules:()=>import('./views/RulesView.vue'),
  alerts:()=>import('./views/AlertsView.vue'),traffic:()=>import('./views/TrafficView.vue'),
  assets:()=>import('./views/InventoryView.vue'),operations:()=>import('./views/OperationsView.vue'),
  notifications:()=>import('./views/NotificationsView.vue'),models:()=>import('./views/ModelsView.vue'),
  assistant:()=>import('./views/AssistantView.vue'),reports:()=>import('./views/ReportsView.vue'),
  retention:()=>import('./views/RetentionView.vue'),incidents:()=>import('./views/IncidentsView.vue'),
  users:()=>import('./views/UsersView.vue'),settings:()=>import('./views/SettingsView.vue'),responseActions:()=>import('./views/ResponseActionsView.vue'),responseDevices:()=>import('./views/ResponseDevicesView.vue'),
}
export const legacyModules:Record<string,string>=manifest.legacy_modules
export function legacyDestination(to:Pick<RouteLocationNormalized,'path'|'query'|'hash'>):RouteLocationRaw {
  const module=legacyModules[to.path.slice(1)]??'sensors'
  const options=platformScreens.filter(screen=>screen.module===module)
  const defaults:Record<string,string>=manifest.legacy_defaults
  const view=typeof to.query.view==='string'?to.query.view:defaults[module]
  const mode=to.query.mode==='rollouts'?'rollouts':'plans'
  const screen=options.find(item=>item.view===view&&(item.view!=='sync'||item.mode===mode))??options.find(item=>item.view===defaults[module])??options[0]!
  const {view:ignoredView,mode:ignoredMode,...query}=to.query
  return {path:screen.path,query,hash:to.hash}
}
export function screenMeta(screen:PlatformScreen) {
  const workspace=navigationWorkspaces.find(item=>item.id===screen.workspace)!
  const related=platformScreens.filter(item=>item.workspace===screen.workspace)
  return {
    title:screen.title,navGroup:workspace.group,navWorkspace:workspace.id,admin:!!screen.admin,
    workspaceView:screen.view,syncMode:screen.mode,
    allowedViews:[...new Set(related.flatMap(item=>item.view?[item.view]:[]))],
    viewPaths:Object.fromEntries(platformScreens.filter(item=>item.module===screen.module&&item.view&&item.mode!=='rollouts').map(item=>[item.view,item.path])),
    modePaths:screen.view==='sync'?{plans:'/detection/rules/sync',rollouts:'/detection/rules/rollouts'}:undefined,
  }
}

export function platformRoutes():RouteRecordRaw[] {
  const routes:RouteRecordRaw[]=[]
  function insert(path:string,record:RouteRecordRaw){
    const parts=path.slice(1).split('/');let level=routes
    parts.forEach((part,index)=>{
      const pathKey=index===0?'/'+part:part
      let node=level.find(item=>item.path===pathKey)
      if(!node){node={path:pathKey,children:[]} as RouteRecordRaw;level.push(node)}
      if(index===parts.length-1)Object.assign(node,record,{path:pathKey})
      else{node.children??=[];level=node.children}
    })
  }
  for(const screen of platformScreens){
    insert(screen.path,{path:screen.path,component:components[screen.module]!,meta:screenMeta(screen),...(screen.module==='screen'?{props:{screen:true}}:{}),...(screen.module==='alerts'?{props:(route:RouteLocationNormalized)=>({advanced:screen.id==='search',window:{start:typeof route.query.start==='string'?route.query.start:undefined,end:typeof route.query.end==='string'?route.query.end:undefined}})}:{})})
  }
  for(const workspace of navigationWorkspaces){
    if(platformScreens.some(item=>item.workspace===workspace.id))continue
    insert(workspacePath(workspace),{path:workspacePath(workspace),component:()=>import('./views/UnavailableView.vue'),meta:{title:workspace.title,navGroup:workspace.group,navWorkspace:workspace.id,admin:true}})
  }
  function defaults(items:RouteRecordRaw[],prefix=''){
    for(const item of items){
      const full=prefix?prefix+'/'+item.path:item.path
      if(!item.component&&item.children?.length){
        item.redirect=full.slice(1) in legacyModules?legacyDestination:{path:full+'/'+item.children[0]!.path}
        defaults(item.children,full)
      }
    }
  }
  defaults(routes)
  for(const path of Object.keys(legacyModules))if(!routes.some(route=>route.path==='/'+path))routes.push({path:'/'+path,redirect:legacyDestination})
  return routes
}

export function navigationForRole(admin:boolean){
  return navigationGroups.flatMap(group=>{
    const children=navigationWorkspaces.filter(workspace=>workspace.group===group.id).flatMap(workspace=>{
      const screens=platformScreens.filter(screen=>screen.workspace===workspace.id&&(!screen.admin||admin))
      if(!screens.length&&!admin)return []
      return [{key:workspace.id,label:workspace.title,path:screens[0]?.path??workspacePath(workspace),available:screens.length>0}]
    })
    return children.length?[{key:group.id,label:group.title,icon:group.icon,children}]:[]
  })
}
