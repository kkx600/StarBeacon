import { createRouter, createWebHashHistory } from 'vue-router'
import { session } from './session'
export const router = createRouter({history: createWebHashHistory(), routes: [
  {path: '/', redirect: '/sensors'},
  {path: '/login', component: () => import('./views/LoginView.vue')},
  {path: '/sensors', component: () => import('./views/SensorsView.vue')},
  {path: '/alerts', component: () => import('./views/AlertsView.vue')},
  {path: '/:pathMatch(.*)*', redirect: '/sensors'},
]})
router.beforeEach(async to => {if (to.path === '/login') return; try {await session.restore()} catch {return '/login'}; if (!session.current.value) return '/login'})
