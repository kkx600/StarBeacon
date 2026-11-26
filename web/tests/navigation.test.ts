import { beforeAll, beforeEach, describe, it, expect, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { defineComponent, h } from 'vue';
import { createRouter, createMemoryHistory, RouterView } from 'vue-router';
import { Menu, Select } from 'ant-design-vue';
import { registerAnt } from '../packages/shared/src/ant';
import NavigationMenu from '../packages/shared/src/components/NavigationMenu.vue';
import WorkspaceTabs from '../packages/shared/src/components/WorkspaceTabs.vue';
import UnavailableView from '../platform/src/views/UnavailableView.vue';
import {
  navigationGroups,
  navigationWorkspaces,
  platformScreens,
  workspacePath,
} from '../packages/shared/src/navigation';
import { navigationForRole, platformRoutes } from '../platform/src/navigation';
import { useWorkspaceView } from '../packages/shared/src/utils/useWorkspaceView';
const { request } = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('../platform/src/session', async () => {
  const { shallowRef } = await import('vue');
  return {
    session: {
      api: { request },
      current: shallowRef({
        id: 'admin_example',
        tenant_id: 'tenant_example',
        role: 'admin',
        csrf_token: 'csrf_example',
      }),
    },
  };
});
beforeEach(() =>
  request.mockReset().mockResolvedValue({
    items: [],
    next_cursor: '',
    available: false,
    execution_available: false,
    model_execution_available: false,
    enabled: false,
    tools: [],
  }),
);
const global = { plugins: [registerAnt] };
async function routerFor(path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes: platformRoutes() });
  await router.push(path);
  await router.isReady();
  return router;
}

describe('业务导航与路由契约', () => {
  beforeAll(async () => {
    // 先加载真实路由组件，避免模块冷编译耗时占用交互用例的期限。
    await Promise.all([
      import('../platform/src/views/RulesView.vue'),
      import('../platform/src/views/CorrelationView.vue'),
    ]);
  });
  it('从检测规则入口可进入关联目录和回测，并能返回规则包，专属选择不泄漏到其他页面', async () => {
    const router = await routerFor('/detection/rules/packages?start=2026-10-19#scope');
    const wrapper = mount(RouterView, { global: { plugins: [registerAnt, router] } });
    async function tab(label: string, path: string) {
      let target;
      await vi.waitFor(() => {
        target = wrapper.findAll('[role=tab]').find(item => item.text() === label);
        expect(target, `工作区应提供 ${label} 入口`).toBeDefined();
      });
      await target!.trigger('click');
      await vi.waitFor(() => expect(router.currentRoute.value.path).toBe(path));
    }
    try {
      await tab('关联规则', '/detection/correlation/rules');
      expect(router.currentRoute.value.fullPath).toBe('/detection/correlation/rules?start=2026-10-19#scope');
      await tab('窗口回测', '/detection/correlation/backtest');
      await router.replace({
        path: router.currentRoute.value.path,
        query: { ...router.currentRoute.value.query, rule_id: 'corr_test', revision: '1' },
        hash: '#scope',
      });
      await tab('规则包', '/detection/rules/packages');
      expect(router.currentRoute.value.fullPath).toBe('/detection/rules/packages?start=2026-10-19#scope');
    } finally {
      wrapper.unmount();
    }
  });
  it.each([
    '/inventory/list',
    '/inventory/groups',
    '/inventory/networks',
    '/inventory/discovery',
    '/ai/assistant',
    '/response/policies',
    '/response/evaluations',
    '/response/plugins',
    '/response/gateway-blocks',
    '/ai/mcp',
    '/reports/plans',
  ])('实际路由 %s 的页面标题与导航名称一致', async path => {
    const router = await routerFor(path),
      screen = platformScreens.find(item => item.path === path)!;
    const wrapper = mount(RouterView, { global: { plugins: [registerAnt, router] } });
    try {
      await flushPromises();
      expect(wrapper.get('h1').text()).toBe(screen.title);
    } finally {
      wrapper.unmount();
    }
  });
  it('十二个业务分组与四十四个原型工作区都有稳定入口，深层页面确实由父子路由匹配', async () => {
    expect(navigationGroups).toHaveLength(12);
    expect(navigationWorkspaces).toHaveLength(44);
    const router = await routerFor('/system/settings/users');
    expect(router.currentRoute.value.matched.map(record => record.path)).toEqual([
      '/system',
      '/system/settings',
      '/system/settings/users',
    ]);
    expect(router.currentRoute.value.meta).toMatchObject({ navGroup: 'system', navWorkspace: 'settings', admin: true });
    for (const screen of platformScreens) {
      const target = router.resolve(screen.path);
      expect(target.matched.at(-1)?.components?.default).toBeTruthy();
      expect(target.meta.title).toBe(screen.title);
      expect(target.meta.workspaceView).toBe(screen.view);
    }
    for (const workspace of navigationWorkspaces)
      expect(router.resolve(workspacePath(workspace)).matched.length).toBeGreaterThan(0);
    for (const path of ['/system', '/system/settings', '/detection', '/detection/rules']) {
      await router.push(path);
      expect(router.currentRoute.value.matched.at(-1)?.components?.default).toBeTruthy();
    }
  });
  it.each([
    ['/overview', '/overview/dashboard'],
    ['/alerts', '/alerts/list'],
    ['/incidents', '/incidents/investigation'],
    ['/inventory', '/inventory/list'],
    ['/traffic', '/traffic/events'],
    ['/traffic/capture', '/traffic/capture/quality'],
    ['/detection', '/detection/rules/packages'],
    ['/detection/rules', '/detection/rules/packages'],
    ['/detection/correlation', '/detection/correlation/rules'],
    ['/response', '/response/policies'],
    ['/notifications', '/notifications/channels'],
    ['/ai', '/ai/models'],
    ['/reports', '/reports/records'],
    ['/sensors', '/sensors/list'],
    ['/system', '/system/settings'],
    ['/system/operations', '/system/operations/health'],
    ['/system/governance', '/system/governance/retention'],
    ['/system/audit', '/system/audit/operations'],
    ['/system/data-sources', '/system/data-sources/syslog'],
  ])('目录父级 %s 进入默认页面 %s，并保留检索窗口及定位标记', async (input, expected) => {
    const router = await routerFor(input + '?start=2026-10-19T00:00:00Z&end=2026-10-20T00:00:00Z#evidence');
    expect(router.currentRoute.value.fullPath).toBe(
      expected + '?start=2026-10-19T00:00:00Z&end=2026-10-20T00:00:00Z#evidence',
    );
  });
  it('两个角色的侧栏只包含可访问的工程工作区，并进入各自的首个可用视图', () => {
    const viewer = navigationForRole(false);
    const admin = navigationForRole(true);
    expect(admin.flatMap(group => group.children)).toHaveLength(28);
    for (const [groups, screens] of [
      [viewer, platformScreens.filter(screen => !screen.admin)],
      [admin, platformScreens],
    ] as const) {
      const items = groups.flatMap(group => group.children);
      expect(new Set(items.map(item => item.key))).toEqual(new Set(screens.map(screen => screen.workspace)));
      for (const item of items) expect(item.path).toBe(screens.find(screen => screen.workspace === item.key)?.path);
    }
    expect(admin.find(group => group.key === 'system')?.children.map(item => item.label)).toContain('平台运维');
  });
  it('页签沿规范路径切换，保留业务条件并支持返回；没有规范路径的视图不改变地址', async () => {
    const router = await routerFor('/system/audit/operations?start=2026-10-19#detail');
    const Probe = defineComponent({
      setup() {
        const { view, change } = useWorkspaceView(['health', 'operations', 'logins', 'missing']);
        return { view, change };
      },
      template:
        '<button id="missing" @click="change(\'missing\')">{{view}}</button><button id="logins" @click="change(\'logins\')">登录日志</button>',
    });
    const wrapper = mount(Probe, { global: { plugins: [router] } });
    expect(wrapper.get('#missing').text()).toBe('operations');
    await wrapper.get('#missing').trigger('click');
    await flushPromises();
    expect(router.currentRoute.value.fullPath).toBe('/system/audit/operations?start=2026-10-19#detail');
    await wrapper.get('#logins').trigger('click');
    await flushPromises();
    expect(router.currentRoute.value.fullPath).toBe('/system/audit/logins?start=2026-10-19#detail');
    router.back();
    await vi.waitFor(() => expect(router.currentRoute.value.path).toBe('/system/audit/operations'));
    wrapper.unmount();
  });
  it('模型页不再混入决策与 MCP，原生发布模式页签保持可操作', async () => {
    const router = await routerFor('/ai/models');
    const wrapper = mount(WorkspaceTabs, {
      props: {
        active: 'providers',
        label: '功能',
        items: [
          { key: 'providers', label: '模型提供方' },
          { key: 'policies', label: '决策策略' },
          { key: 'mcp', label: 'MCP 服务' },
        ],
      },
      global: { plugins: [registerAnt, router] },
    });
    expect(wrapper.find('nav').exists()).toBe(false);
    await router.push('/detection/rules/sync');
    await wrapper.setProps({
      active: 'plans',
      items: [
        { key: 'plans', label: '单探针计划' },
        { key: 'rollouts', label: '分批发布' },
      ],
    });
    expect(wrapper.text()).toContain('分批发布');
    wrapper.unmount();
  });
  it('展开祖先分组、切换与折叠不会丢失当前选中工作区', async () => {
    const items = [
      { key: 'group:system', label: '系统管理', children: [{ key: 'workspace:settings', label: '系统设置' }] },
      { key: 'other', label: '其他', icon: () => h('span') },
    ];
    const wrapper = mount(NavigationMenu, { props: { items, current: 'workspace:settings' }, global });
    expect(wrapper.getComponent(Menu).props('openKeys')).toEqual(['group:system']);
    await wrapper.setProps({ collapsed: true });
    expect(wrapper.getComponent(Menu).props('openKeys')).toEqual([]);
    await wrapper.setProps({ collapsed: false });
    expect(wrapper.getComponent(Menu).props('selectedKeys')).toEqual(['workspace:settings']);
    wrapper.getComponent(Menu).vm.$emit('click', { key: 'workspace:settings' });
    expect(wrapper.emitted('navigate')).toEqual([['workspace:settings']]);
    await wrapper.setProps({ current: 'missing' });
    expect(wrapper.getComponent(Menu).props('openKeys')).toEqual([]);
    wrapper.unmount();
  });
  it('系统设置从分类进入真实用户管理及功能目录，隐藏尚未交付的设置分类', async () => {
    const router = await routerFor('/system/settings');
    const wrapper = mount(RouterView, { global: { plugins: [registerAnt, router] } });
    await flushPromises();
    const categories = wrapper.get('nav[aria-label="设置分类"]');
    expect(categories.findAll('a').map(link => link.text())).toEqual([
      '用户管理',
      '网关阻断',
      '全流量存储',
      '功能目录',
    ]);
    expect(categories.get('[aria-current="page"]').text()).toBe('用户管理');
    expect(wrapper.get('section[aria-label="用户管理"] h2').text()).toBe('用户管理');
    expect(request.mock.calls.some(([path]) => String(path).startsWith('/users?'))).toBe(true);
    await categories.get('a[href="/system/settings?section=features"]').trigger('click');
    await vi.waitFor(() => expect(wrapper.get('section[aria-label="功能目录"] h2').text()).toBe('功能目录'));
    expect(wrapper.findAll('.ant-table-wrapper')).toHaveLength(1);
    expect(wrapper.text()).toContain('当前版本未提供');
    const disabled = wrapper.findAll('button').filter(button => button.attributes('disabled') !== undefined);
    expect(disabled.length).toBeGreaterThan(0);
    await wrapper.get('input').setValue('不存在的设置');
    expect(wrapper.text()).toContain('没有匹配的功能');
    await wrapper.get('input').setValue('');
    wrapper.getComponent(Select).vm.$emit('update:value', 'all');
    await flushPromises();
    expect(wrapper.text()).toContain('检测规则');
    const rows = wrapper.findAll('tr[data-row-key]');
    expect(rows).toHaveLength(43);
    const unavailable = rows.filter(row => row.text().includes('当前版本未提供'));
    expect(unavailable).toHaveLength(16);
    expect(unavailable.every(row => row.get('button').attributes('disabled') !== undefined)).toBe(true);
    expect(unavailable.find(row => row.attributes('data-row-key') === 'ai-ops')?.text()).toContain('AI 值守');
    expect(unavailable.find(row => row.attributes('data-row-key') === 'users')?.text()).toContain('认证与授权');
    await categories.get('a[href="/system/settings/users"]').trigger('click');
    await vi.waitFor(() => expect(router.currentRoute.value.path).toBe('/system/settings/users'));
    await vi.waitFor(() => expect(wrapper.get('section[aria-label="用户管理"] h2').text()).toBe('用户管理'));
    wrapper.unmount();
  });
  it('尚未提供的目录清楚说明范围，系统设置与总览返回目标有效', async () => {
    const router = await routerFor('/system/tenants');
    const wrapper = mount(UnavailableView, { global: { plugins: [registerAnt, router] } });
    expect(wrapper.get('h1').text()).toBe('租户管理');
    expect(wrapper.text()).toContain('当前版本未提供此功能');
    async function follow(label: string, path: string) {
      let stop = () => {};
      const arrived = new Promise<void>(resolve => {
        stop = router.afterEach(to => {
          if (to.path === path) resolve();
        });
      });
      try {
        await wrapper
          .findAll('button')
          .find(button => button.text() === label)!
          .trigger('click');
        await arrived;
        expect(router.currentRoute.value.path).toBe(path);
      } finally {
        stop();
      }
    }
    try {
      await follow('查看系统设置', '/system/settings');
      await follow('返回态势总览', '/overview/dashboard');
    } finally {
      wrapper.unmount();
    }
  });
  it('AI 值守的规范地址仍加载当前版本未提供页面', async () => {
    const router = await routerFor('/ai/ai-ops');
    const wrapper = mount(RouterView, { global: { plugins: [registerAnt, router] } });
    try {
      await flushPromises();
      expect(router.currentRoute.value.meta.admin).toBe(true);
      expect(wrapper.get('h1').text()).toBe('AI 值守');
      expect(wrapper.text()).toContain('当前版本未提供此功能');
    } finally {
      wrapper.unmount();
    }
  });
});
