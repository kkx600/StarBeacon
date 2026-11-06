import {platformScreens,navigationWorkspaces,workspacePath} from '@starbeacon/shared/navigation.ts'
import {pageById} from './data/catalog'
import {collectorPrototypeScreens,collectorPreviewCanonical} from './data/collectorNavigation'
import { createRouter, createWebHistory } from 'vue-router'

export const router=createRouter({
  history:createWebHistory(import.meta.env.BASE_URL),
  routes:[
    {path:'/',redirect:'/page/overview'},
    ...platformScreens.filter(screen=>pageById.has(screen.id)).map(screen=>({path:screen.path,component:()=>import('./views/PageView.vue'),meta:{previewPage:screen.id}})),
    ...navigationWorkspaces.filter(workspace=>!platformScreens.some(screen=>screen.workspace===workspace.id)).map(workspace=>({path:workspacePath(workspace),component:()=>import('./views/PageView.vue'),meta:{previewPage:workspace.pages[0]}})),
    {path:'/page/:id',component:()=>import('./views/PageView.vue')},
    {path:'/collector',redirect:'/collector/overview/status'},
    ...collectorPrototypeScreens.map(screen=>({path:screen.path,component:()=>import('./views/CollectorView.vue'),meta:{collectorView:screen.view,collectorPage:screen.page}})),
    {path:'/collector/auth/:mode',component:()=>import('./views/CollectorAuthView.vue')},
    {path:'/collector/:id',component:()=>import('./views/CollectorView.vue')},
    {path:'/catalog',component:()=>import('./views/CatalogView.vue')},
    {path:'/auth/:mode',component:()=>import('./views/AuthView.vue')},
    {path:'/status/:code',component:()=>import('./views/StatusView.vue')},
    {path:'/:pathMatch(.*)*',redirect:'/status/404'},
  ],
  scrollBehavior:()=>({top:0}),
})

// 页面目录与内部链接使用 /page/:id；已绑定工程路径的功能进入同一规范路径，保留原型状态等查询参数。
router.beforeEach(to=>{
  const collectorDestination=collectorPreviewCanonical(to)
  if(collectorDestination)return collectorDestination
  if(!to.path.startsWith('/page/'))return
  const id=String(to.params.id??'')
  const screen=platformScreens.find(item=>item.id===id)
  if(screen)return {path:screen.path,query:to.query,hash:to.hash}
})
