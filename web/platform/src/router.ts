import { createRouter, createWebHistory } from 'vue-router';
import { platformRoutes } from './navigation';
import { session } from './session';
export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  scrollBehavior: () => ({ top: 0 }),
  routes: [
    { path: '/', redirect: '/overview/dashboard' },
    { path: '/login', component: () => import('./views/LoginView.vue') },
    { path: '/system/accounts', redirect: '/system/settings/users' },
    { path: '/system/accounts/users', redirect: '/system/settings/users' },
    ...platformRoutes(),
    {
      path: '/:pathMatch(.*)*',
      component: () => import('@starbeacon/shared/components/NotFound.vue'),
      props: { home: '/sensors/list' },
    },
  ],
});
router.beforeEach(async to => {
  if (to.path === '/login') return;
  try {
    await session.restore();
  } catch {
    return { path: '/login', query: { redirect: to.fullPath } };
  }
  if (!session.current.value) return { path: '/login', query: { redirect: to.fullPath } };
  if (to.meta.admin && session.current.value.role !== 'admin') return '/sensors/list';
});
