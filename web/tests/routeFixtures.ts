import type { Component } from 'vue';
import type { RouteRecordRaw } from 'vue-router';
import { platformScreens } from '../packages/shared/src/navigation';
import { screenMeta } from '../platform/src/navigation';
import { collectorMeta, collectorScreens } from '../collector/src/navigation';
// 组件测试沿实际导航目录注册规范路径及页签元数据，页面选择与正式路由一致，不再依赖查询参数。
export function platformScreenRoutes(component: Component): RouteRecordRaw[] {
  return platformScreens.map(screen => ({ path: screen.path, component, meta: screenMeta(screen) }));
}
export function collectorScreenRoutes(component: Component): RouteRecordRaw[] {
  return collectorScreens.map(screen => ({ path: screen.path, component, meta: collectorMeta(screen.view) }));
}
