import {platformScreens,navigationWorkspaces,workspacePath} from '@starbeacon/shared/navigation.ts'
import {pageById} from './data/catalog'
import {legacyPages} from './data/navigation'
import { createRouter, createWebHistory } from 'vue-router'
import {migrateLegacyHash} from '../../web/packages/shared/src/utils/history'

migrateLegacyHash(import.meta.env.BASE_URL)
export const router=createRouter({
  history:createWebHistory(import.meta.env.BASE_URL),
  routes:[
    {path:'/',redirect:'/page/overview'},
    ...Object.entries(legacyPages).map(([legacy,id])=>({path:`/page/${legacy}`,redirect:(to:import('vue-router').RouteLocation)=>({path:`/page/${id}`,query:to.query,hash:to.hash})})),
    ...platformScreens.filter(screen=>pageById.has(screen.id)).map(screen=>({path:screen.path,component:()=>import('./views/PageView.vue'),meta:{previewPage:screen.id}})),
    ...navigationWorkspaces.filter(workspace=>!platformScreens.some(screen=>screen.workspace===workspace.id)).map(workspace=>({path:workspacePath(workspace),component:()=>import('./views/PageView.vue'),meta:{previewPage:workspace.pages[0]}})),
    {path:'/page/:id',component:()=>import('./views/PageView.vue')},
    {path:'/collector',redirect:'/collector/overview'},
    {path:'/collector/auth/:mode',component:()=>import('./views/CollectorAuthView.vue')},
    {path:'/collector/:id',component:()=>import('./views/CollectorView.vue')},
    {path:'/catalog',component:()=>import('./views/CatalogView.vue')},
    {path:'/auth/:mode',component:()=>import('./views/AuthView.vue')},
    {path:'/status/:code',component:()=>import('./views/StatusView.vue')},
    {path:'/:pathMatch(.*)*',redirect:'/status/404'},
  ],
  scrollBehavior:()=>({top:0}),
})

router.beforeEach(to=>{
  if(!to.path.startsWith('/page/'))return
  let id=String(to.params.id??'')
  const query={...to.query}
  if(id==='assets'&&query.view==='discovery'){id='discovery';delete query.view}
  if(id==='sensors'&&query.view==='quality'){id='capture-quality';delete query.view}
  if(id==='rule-sync'&&query.mode==='rollouts'){id='rule-rollouts';delete query.mode}
  const screen=platformScreens.find(item=>item.id===id)
  if(screen)return {path:screen.path,query,hash:to.hash}
})
