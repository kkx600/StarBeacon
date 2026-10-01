import {legacyPages} from './data/navigation'
import { createRouter, createWebHistory } from 'vue-router'
import {migrateLegacyHash} from '../../web/packages/shared/src/utils/history'

migrateLegacyHash(import.meta.env.BASE_URL)
export const router=createRouter({
  history:createWebHistory(import.meta.env.BASE_URL),
  routes:[
    {path:'/',redirect:'/page/overview'},
    ...Object.entries(legacyPages).map(([legacy,id])=>({path:`/page/${legacy}`,redirect:(to:import('vue-router').RouteLocation)=>({path:`/page/${id}`,query:to.query,hash:to.hash})})),
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
