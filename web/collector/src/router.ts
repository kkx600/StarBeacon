import { createRouter, createWebHashHistory } from 'vue-router'
import { session } from './session'
export const router = createRouter({history:createWebHashHistory(),routes:[{path:'/',redirect:'/network'},{path:'/login',component:()=>import('./views/LoginView.vue')},{path:'/network',component:()=>import('./views/CollectorView.vue')},{path:'/:pathMatch(.*)*',redirect:'/network'}]})
router.beforeEach(async to=>{if(to.path==='/login')return;try{await session.restore()}catch{return '/login'};if(!session.current.value)return '/login'})
