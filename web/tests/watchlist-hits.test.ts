import { webcrypto, randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { defineComponent, h, shallowRef } from 'vue';
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { registerAnt } from '../packages/shared/src/ant';
import { ApiError } from '../packages/shared/src/api';
import { goJSONDigest } from '../packages/shared/src/utils/goJSONDigest';
import {
  readWatchlistAlertHits,
  readWatchlistHitPage,
  readWatchlistImpact,
  watchlistHitPath,
  watchlistHitQuery,
  watchlistImpactRequest,
  type WatchlistHit,
  type WatchlistHitPage,
  type WatchlistImpact,
  type WatchlistHitQuery,
} from '../packages/shared/src/watchlists';
import WatchlistHits from '../packages/shared/src/components/WatchlistHits.vue';
import WatchlistImpactView from '../packages/shared/src/components/WatchlistImpact.vue';
import MetricBar from '../packages/shared/src/components/MetricBar.vue';
import { useWatchlistHits } from '../platform/src/features/watchlists/useWatchlistHits';
import { useWatchlistImpact } from '../platform/src/features/watchlists/useWatchlistImpact';
import { principal, click, deferred } from './fixtures';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
const user = shallowRef<typeof principal | null>(principal),
  wrappers: VueWrapper[] = [];
vi.mock('../platform/src/session', () => ({
  session: {
    api: { request },
    get current() {
      return user;
    },
  },
}));

const list = 'watch_office',
  digest64 = 'a'.repeat(64);
const query = (): WatchlistHitQuery => watchlistHitQuery(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');

async function hit(extra: Partial<WatchlistHit> = {}, tenant = principal.tenant_id): Promise<WatchlistHit> {
  const base = { list_id: list, list_revision: 3, event_id: 'evt_1', raw_sha256: digest64, ...extra };
  const id =
    'whit_' +
    (await goJSONDigest([tenant, base.list_id, base.list_revision, base.event_id, base.raw_sha256])).slice(0, 56);
  return {
    schema_version: 'watchlist-hit.v1',
    id,
    list_id: base.list_id,
    list_revision: base.list_revision,
    definition_sha256: 'b'.repeat(64),
    event_id: base.event_id,
    raw_sha256: base.raw_sha256,
    sensor_id: 'probe_1',
    registration_id: 'register_1',
    matches: [{ field: 'source.ip', value: '192.0.2.10' }],
    severity: 'high',
    rule_id: '9900001',
    rule_name: 'HTTP API access',
    observed_at: '2026-11-05T12:00:00Z',
    received_at: '2026-11-05T12:00:01Z',
    created_at: '2026-11-05T12:00:02Z',
    expires_at: '2027-05-04T12:00:02Z',
    ...extra,
  } as WatchlistHit;
}
async function page(extra: Partial<WatchlistHitPage> = {}): Promise<WatchlistHitPage> {
  return { items: [await hit()], next_cursor: '', observed_at: '2026-11-06T00:00:00Z', capped_days: [], ...extra };
}
async function cursorFor(h: WatchlistHit, q = query(), tenant = principal.tenant_id): Promise<string> {
  const scope = await goJSONDigest({
    tenant,
    query: { list_id: q.list_id, start: q.start, end: q.end, cursor: '', limit: q.limit },
  });
  return btoa(JSON.stringify({ time: h.observed_at, id: h.id, scope }))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}
const impactInput = () => watchlistImpactRequest(3, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
function impact(extra: Partial<WatchlistImpact> = {}): WatchlistImpact {
  return {
    schema_version: 'watchlist-impact.v1',
    list_id: list,
    list_revision: 3,
    definition_sha256: 'b'.repeat(64),
    kind: 'observe',
    match_type: 'ip',
    current: true,
    active: true,
    start: '2026-11-05T00:00:00Z',
    end: '2026-11-06T00:00:00Z',
    checked_at: '2026-11-06T00:00:00Z',
    fields: ['source.ip', 'destination.ip'],
    total: 1,
    values: [{ value: '192.0.2.10', count: 1 }],
    samples: [
      {
        event_id: 'evt_1',
        raw_sha256: digest64,
        '@timestamp': '2026-11-05T12:00:00Z',
        sensor_id: 'probe_1',
        registration_id: 'register_1',
        severity: 'high',
        rule_name: 'HTTP API access',
        matches: [{ field: 'source.ip', value: '192.0.2.10' }],
      },
    ],
    hits_recorded: false,
    execution_authorized: false,
    ...extra,
  } as WatchlistImpact;
}
function host<T>(factory: () => T) {
  let state!: T;
  const wrapper = mount(
    defineComponent({
      setup() {
        state = factory();
        return () => h('div');
      },
    }),
  );
  wrappers.push(wrapper);
  return { state, wrapper };
}

beforeEach(() => {
  request.mockReset();
  user.value = principal;
  vi.stubGlobal('crypto', { subtle: webcrypto.subtle, randomUUID });
  vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-11-06T00:00:00Z'));
});
afterEach(() => {
  wrappers.splice(0).forEach(w => w.unmount());
  vi.useRealTimers();
  document.body.replaceChildren();
  vi.unstubAllGlobals();
});

describe('命中查询窗口与路径', () => {
  it('窗口按整秒 UTC 冻结，结束时刻不包含在查询内', () => {
    const q = watchlistHitQuery(list, '2026-11-05T00:00:00.750Z', '2026-11-06T00:00:00Z');
    expect(q).toEqual({
      list_id: list,
      start: '2026-11-05T00:00:00Z',
      end: '2026-11-06T00:00:00Z',
      cursor: '',
      limit: 20,
    });
    expect(watchlistHitPath(q)).toBe(
      `/watchlists/${list}/hits?start=2026-11-05T00%3A00%3A00Z&end=2026-11-06T00%3A00%3A00Z&limit=20`,
    );
    expect(watchlistHitPath({ ...q, cursor: 'abc' })).toContain('&cursor=abc');
  });
  it('拒绝倒置、超过 31 天、越界页大小与超长游标', () => {
    for (const args of [
      ['BAD', '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z'],
      [list, '2026-11-06T00:00:00Z', '2026-11-05T00:00:00Z'],
      [list, '2026-11-05T00:00:00Z', '2026-11-05T00:00:00Z'],
      [list, '2026-10-01T00:00:00Z', '2026-11-06T00:00:00Z'],
      [list, 'not-a-date', '2026-11-06T00:00:00Z'],
      [list, '1999-01-01T00:00:00Z', '1999-02-01T00:00:00Z'],
    ] as [string, string, string][])
      expect(() => watchlistHitQuery(...args)).toThrow();
    expect(() => watchlistHitQuery(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z', '', 0)).toThrow();
    expect(() => watchlistHitQuery(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z', '', 101)).toThrow();
    expect(() => watchlistHitQuery(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z', 'x'.repeat(513))).toThrow();
    expect(watchlistHitQuery(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z', '', 100).limit).toBe(100);
  });
});

describe('命中页读取器', () => {
  it('接受合法命中页并保留截断日与游标', async () => {
    const q = query(),
      only = await hit(),
      next = await cursorFor(only, q);
    const value = await page({
      next_cursor: '',
      capped_days: [{ day: '2026-11-05', recorded: 10000, capped_at: '2026-11-05T23:00:00Z' }],
    });
    await expect(readWatchlistHitPage(value, q, principal.tenant_id)).resolves.toBe(value);
    const full = await page({ items: Array.from({ length: q.limit }, () => only), next_cursor: next });
    // 同一命中重复出现违反倒序唯一性，游标合法也不接受。
    await expect(readWatchlistHitPage(full, q, principal.tenant_id)).rejects.toThrow();
  });
  it('拒绝改写的命中标识、跨租户记录与窗口外观测时间', async () => {
    const q = query();
    await expect(
      readWatchlistHitPage(
        await page({ items: [{ ...(await hit()), id: 'whit_' + '0'.repeat(56) }] }),
        q,
        principal.tenant_id,
      ),
    ).rejects.toThrow();
    // 标识绑定租户：同一条记录换租户核对必然不一致。
    await expect(readWatchlistHitPage(await page(), q, 't_other')).rejects.toThrow();
    await expect(
      readWatchlistHitPage(
        await page({ items: [await hit({ observed_at: '2026-11-06T00:00:00Z' })] }),
        q,
        principal.tenant_id,
      ),
    ).rejects.toThrow();
    await expect(
      readWatchlistHitPage(
        await page({ items: [await hit({ observed_at: '2026-11-04T00:00:00Z' })] }),
        q,
        principal.tenant_id,
      ),
    ).rejects.toThrow();
    await expect(
      readWatchlistHitPage(await page({ items: [await hit({ list_id: 'other_list' })] }), q, principal.tenant_id),
    ).rejects.toThrow();
  });
  it('拒绝多余字段、非法严重级别、重复匹配项与错误排序', async () => {
    const q = query(),
      one = await hit();
    await expect(readWatchlistHitPage({ ...(await page()), extra: true }, q, principal.tenant_id)).rejects.toThrow();
    await expect(
      readWatchlistHitPage(
        await page({ items: [{ ...one, extra: true } as unknown as WatchlistHit] }),
        q,
        principal.tenant_id,
      ),
    ).rejects.toThrow();
    await expect(
      readWatchlistHitPage(
        await page({ items: [await hit({ severity: 'critical' as WatchlistHit['severity'] })] }),
        q,
        principal.tenant_id,
      ),
    ).rejects.toThrow();
    await expect(
      readWatchlistHitPage(
        await page({
          items: [
            await hit({
              matches: [
                { field: 'source.ip', value: '192.0.2.10' },
                { field: 'source.ip', value: '192.0.2.10' },
              ],
            }),
          ],
        }),
        q,
        principal.tenant_id,
      ),
    ).rejects.toThrow();
    await expect(
      readWatchlistHitPage(await page({ items: [await hit({ matches: [] })] }), q, principal.tenant_id),
    ).rejects.toThrow();
    await expect(
      readWatchlistHitPage(
        await page({ items: [await hit({ matches: [{ field: 'tls.sni', value: '192.0.2.10' }] })] }),
        q,
        principal.tenant_id,
      ),
    ).rejects.toThrow();
    const earlier = await hit({ event_id: 'evt_2', observed_at: '2026-11-05T01:00:00Z' });
    // 倒序要求先新后旧；升序材料说明本页不完整。
    await expect(readWatchlistHitPage(await page({ items: [earlier, one] }), q, principal.tenant_id)).rejects.toThrow();
    await expect(
      readWatchlistHitPage(await page({ items: [one, earlier] }), q, principal.tenant_id),
    ).resolves.toBeTruthy();
  });
  it('游标必须绑定当前窗口与末条记录，篡改或跨窗口复用都拒绝', async () => {
    const q = query(),
      items = Array.from({ length: q.limit }, () => null);
    const only = await hit(),
      full = (cursor: string) => ({
        items: items.map(() => only),
        next_cursor: cursor,
        observed_at: '2026-11-06T00:00:00Z',
        capped_days: [],
      });
    const other = await cursorFor(only, { ...q, limit: 50 });
    for (const cursor of [
      '!!!',
      await cursorFor(await hit({ event_id: 'evt_9' }), q),
      other,
      await cursorFor(only, q, 't_other'),
    ])
      await expect(readWatchlistHitPage(full(cursor), q, principal.tenant_id)).rejects.toThrow();
    // 未满页却给出续读游标，说明服务端分页与页大小不一致。
    await expect(
      readWatchlistHitPage(await page({ next_cursor: await cursorFor(only, q) }), q, principal.tenant_id),
    ).rejects.toThrow();
  });
  it('截断日必须落在窗口内且按日期倒序', async () => {
    const q = query();
    for (const days of [
      [{ day: '2026-11-01', recorded: 1, capped_at: '2026-11-01T00:00:00Z' }],
      [{ day: '2026-11-05', recorded: 1, capped_at: 'bad' }],
      [{ day: '2026-11-05', recorded: -1, capped_at: '2026-11-05T00:00:00Z' }],
      [
        { day: '2026-11-05', recorded: 1, capped_at: '2026-11-05T00:00:00Z' },
        { day: '2026-11-06', recorded: 1, capped_at: '2026-11-06T00:00:00Z' },
      ],
    ])
      await expect(
        readWatchlistHitPage(
          await page({ capped_days: days as WatchlistHitPage['capped_days'] }),
          q,
          principal.tenant_id,
        ),
      ).rejects.toThrow();
  });
});

describe('告警命中读取器', () => {
  it('摘要与告警身份一致才接受，并拒绝重复命中', async () => {
    const value = { items: [await hit()], observed_at: '2026-11-06T00:00:00Z' };
    await expect(readWatchlistAlertHits(value, principal.tenant_id, 'evt_1', digest64)).resolves.toBe(value);
    await expect(readWatchlistAlertHits(value, principal.tenant_id, 'evt_1', 'c'.repeat(64))).rejects.toThrow();
    await expect(readWatchlistAlertHits(value, principal.tenant_id, 'evt_2', digest64)).rejects.toThrow();
    const twice = { items: [await hit(), await hit()], observed_at: '2026-11-06T00:00:00Z' };
    await expect(readWatchlistAlertHits(twice, principal.tenant_id, 'evt_1', digest64)).rejects.toThrow();
    await expect(
      readWatchlistAlertHits({ ...value, extra: 1 }, principal.tenant_id, 'evt_1', digest64),
    ).rejects.toThrow();
  });
});

describe('历史影响读取器', () => {
  it('接受与本次核对范围一致的结果', () => {
    const value = impact();
    expect(readWatchlistImpact(value, list, impactInput())).toBe(value);
  });
  it('拒绝字段范围、修订或窗口与本次核对不一致的结果', () => {
    const input = impactInput();
    expect(() => readWatchlistImpact(impact({ list_revision: 2 }), list, input)).toThrow();
    expect(() => readWatchlistImpact(impact(), 'other_list', input)).toThrow();
    expect(() => readWatchlistImpact(impact({ end: '2026-11-07T00:00:00Z' }), list, input)).toThrow();
    // 预览字段由匹配方式决定；多给 TLS SNI 说明材料超出可检索范围。
    expect(() =>
      readWatchlistImpact(impact({ fields: ['source.ip', 'destination.ip', 'tls.sni'] }), list, input),
    ).toThrow();
    expect(() => readWatchlistImpact(impact({ fields: ['destination.ip', 'source.ip'] }), list, input)).toThrow();
    expect(() => readWatchlistImpact(impact({ match_type: 'domain' }), list, input)).toThrow();
  });
  it('拒绝部分计数、越界计数与样本数量不符', () => {
    const input = impactInput();
    expect(() => readWatchlistImpact(impact({ values: [] }), list, input)).toThrow();
    expect(() => readWatchlistImpact(impact({ values: [{ value: '192.0.2.10', count: 2 }] }), list, input)).toThrow();
    expect(() =>
      readWatchlistImpact(
        impact({
          values: [
            { value: '192.0.2.10', count: 1 },
            { value: '192.0.2.10', count: 0 },
          ],
        }),
        list,
        input,
      ),
    ).toThrow();
    expect(() => readWatchlistImpact(impact({ values: [{ value: 'bad value', count: 1 }] }), list, input)).toThrow();
    expect(() => readWatchlistImpact(impact({ samples: [] }), list, input)).toThrow();
    // 没有任何命中时计数为 0 且无样本，是合法的空结果而不是不完整。
    expect(
      readWatchlistImpact(impact({ total: 0, values: [{ value: '192.0.2.10', count: 0 }], samples: [] }), list, input)
        .total,
    ).toBe(0);
  });
  it('拒绝乱序样本、越界时间戳与已登记或已授权标记', () => {
    const input = impactInput(),
      base = impact();
    const second = { ...base.samples[0]!, event_id: 'evt_2', '@timestamp': '2026-11-05T13:00:00Z' };
    // 样本按时间倒序；升序说明检索材料与排序契约不一致。
    expect(() => readWatchlistImpact(impact({ total: 2, samples: [base.samples[0]!, second] }), list, input)).toThrow();
    expect(
      readWatchlistImpact(impact({ total: 2, samples: [second, base.samples[0]!] }), list, input).samples,
    ).toHaveLength(2);
    expect(() =>
      readWatchlistImpact(
        impact({ samples: [{ ...base.samples[0]!, '@timestamp': '2026-11-06T00:00:00Z' }] }),
        list,
        input,
      ),
    ).toThrow();
    expect(() => readWatchlistImpact(impact({ hits_recorded: true as unknown as false }), list, input)).toThrow();
    expect(() =>
      readWatchlistImpact(impact({ execution_authorized: true as unknown as false }), list, input),
    ).toThrow();
    expect(() =>
      readWatchlistImpact(
        impact({ samples: [{ ...base.samples[0]!, matches: [{ field: 'tls.sni', value: 'api.example.com' }] }] }),
        list,
        input,
      ),
    ).toThrow();
  });
  it('修订与窗口在提交前校验', () => {
    for (const args of [
      [0, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z'],
      [1, '2026-11-06T00:00:00Z', '2026-11-05T00:00:00Z'],
      [1, '2026-10-01T00:00:00Z', '2026-11-06T00:00:00Z'],
      [1.5, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z'],
    ] as [number, string, string][])
      expect(() => watchlistImpactRequest(...args)).toThrow();
    expect(watchlistImpactRequest(3, '2026-11-05T00:00:00.900Z', '2026-11-06T00:00:00Z')).toEqual({
      revision: 3,
      start: '2026-11-05T00:00:00Z',
      end: '2026-11-06T00:00:00Z',
    });
  });
});

describe('命中列表交互', () => {
  async function hits(extra: Record<string, unknown> = {}) {
    const w = mount(WatchlistHits, {
      attachTo: document.body,
      props: { listId: list, page: await page(), pending: false, error: '', loaded: true, pages: 1, ...extra },
      global: { plugins: [registerAnt] },
    });
    wrappers.push(w);
    await flushPromises();
    return w;
  }
  it('严重级别文案与告警列表一致，字段名用中性标签', async () => {
    const w = await hits();
    expect(w.text()).toContain('高危');
    expect(w.find('.status-high').exists()).toBe(true);
    expect(w.find('.status-neutral').text()).toBe('源 IP');
    expect(w.text()).toContain('HTTP API access');
    expect(w.text()).toContain('按当时修订固化');
    expect(w.text()).toContain('命中不表示攻击成立');
  });
  it('规则名称缺失时给出业务原因而不是空白', async () => {
    const w = await hits({ page: await page({ items: [await hit({ rule_name: '' })] }) });
    expect(w.text()).toContain('规则名称未记录');
  });
  it('截断日提示列出具体日期与单日上限', async () => {
    const w = await hits({
      page: await page({
        capped_days: [
          { day: '2026-11-05', recorded: 10000, capped_at: '2026-11-05T23:00:00Z' },
          { day: '2026-11-04', recorded: 10000, capped_at: '2026-11-04T23:00:00Z' },
        ],
      }),
    });
    expect(w.text()).toContain('2026-11-05、2026-11-04');
    expect(w.text()).toContain('10,000');
    expect(w.text()).toContain('列表不完整');
  });
  it('读取失败且已有数据时保留上次结果并提示更新失败', async () => {
    const w = await hits({ error: '命中记录读取超时，请重试。', loaded: true });
    expect(w.text()).toContain('命中记录更新失败，当前保留上次读取结果');
    expect(w.text()).toContain('HTTP API access');
    expect(w.find('.state-panel').exists()).toBe(false);
  });
  it('首次失败显示可重试的错误态，不显示表格', async () => {
    const w = await hits({ error: '命中记录读取失败，请重试。', loaded: false, page: await page({ items: [] }) });
    expect(w.find('.state-panel').exists()).toBe(true);
    expect(w.text()).toContain('暂时无法读取数据');
    await click('重试', w.element);
    expect(w.emitted('retry')).toHaveLength(1);
  });
  it('空态说明命中只关联修订保存后的新告警', async () => {
    const w = await hits({ page: await page({ items: [] }) });
    expect(w.text()).toContain('当前时间窗内没有命中记录');
    expect(w.text()).toContain('历史影响');
  });
  it('挂载即按默认窗口查询，翻页按钮受游标与读取状态约束', async () => {
    const w = await hits();
    expect(w.emitted('query')).toHaveLength(1);
    const [start, end] = w.emitted('query')![0] as [string, string];
    expect(Date.parse(end + 'Z') - Date.parse(start + 'Z')).toBe(86400000);
    await click('查询命中', w.element);
    expect(w.emitted('query')).toHaveLength(2);
    await w.setProps({ page: await page({ next_cursor: 'abc' }), pages: 1 });
    await click('下一页', w.element);
    expect(w.emitted('next')).toHaveLength(1);
    await w.setProps({ pages: 2 });
    await click('上一页', w.element);
    expect(w.emitted('previous')).toHaveLength(1);
  });
});

describe('历史影响界面', () => {
  async function view(extra: Record<string, unknown> = {}) {
    const w = mount(WatchlistImpactView, {
      attachTo: document.body,
      props: {
        listId: list,
        revision: 3,
        maximum: 3,
        result: null,
        pending: false,
        error: '',
        incomplete: false,
        ...extra,
      },
      global: { plugins: [registerAnt] },
    });
    wrappers.push(w);
    await flushPromises();
    return w;
  }
  it('检索不完整时只给结论不给任何部分数字', async () => {
    const w = await view({ result: impact(), incomplete: true });
    expect(w.text()).toContain('历史检索结果不完整，本次未交付计数');
    expect(w.text()).not.toContain('192.0.2.10');
    expect(w.findComponent(MetricBar).exists()).toBe(false);
    expect(w.findAll('.ant-table-wrapper')).toHaveLength(0);
  });
  it('交付结果时显示总数、核对时间与参与字段', async () => {
    const w = await view({ result: impact({ total: 1234 }) });
    expect(w.text()).toContain('1,234');
    expect(w.text()).toContain('命中告警总数');
    // 参与字段只列实际查询的已索引字段；边界提示里出现的 TLS SNI 是说明文案，不计入字段标签。
    const tags = w.findAll('.watchlist-impact-tags .status').map(tag => tag.text());
    expect(tags).toEqual(['源 IP', '目的 IP']);
    expect(w.text()).toContain('本次未登记任何命中');
  });
  it('边界提示说明预览不登记命中也不在范围内检索 SNI 与 DNS', async () => {
    const w = await view();
    expect(w.text()).toContain('不登记命中');
    expect(w.text()).toContain('TLS SNI 与 DNS 查询名没有检索字段');
    expect(w.text()).toContain('点击“执行预览”');
  });
  it('修订越界时禁止提交，合法时带窗口发起预览', async () => {
    const w = await view();
    await click('执行预览', w.element);
    expect(w.emitted('run')).toHaveLength(1);
    expect((w.emitted('run')![0] as unknown[])[0]).toBe(3);
    await w.setProps({ revision: 9 });
    await flushPromises();
    expect(w.find('button[type=submit]').attributes('disabled')).toBeDefined();
  });
});

describe('命中读取 composable', () => {
  it('游标失效返回 400 时清空游标并从窗口终点重读，不提示服务不可用', async () => {
    // 首页按页大小填满并给出合法续读游标，才能进入翻页路径。
    const q = query(),
      items: WatchlistHit[] = [];
    for (let i = 0; i < q.limit; i++)
      items.push(
        await hit({
          event_id: 'evt_' + String(i).padStart(3, '0'),
          observed_at: new Date(Date.parse('2026-11-05T12:00:00Z') - i * 60000).toISOString().replace('.000Z', 'Z'),
        }),
      );
    const firstPage = await page({ items, next_cursor: await cursorFor(items[q.limit - 1]!, q) });
    request.mockResolvedValueOnce(firstPage);
    const { state } = host(() => useWatchlistHits());
    state.load(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.loaded.value).toBe(true));
    // 翻页时游标被平台判为非法；应清空游标重读窗口终点，而不是报服务不可用。
    request.mockRejectedValueOnce(new ApiError(400, 'invalid_watchlist', '请核对名单、规范值、探针范围和有效期'));
    request.mockResolvedValueOnce(firstPage);
    state.next();
    await vi.waitFor(() => expect(state.pending.value).toBe(false));
    expect(state.error.value).toBe('');
    expect(state.cursors.value).toEqual(['']);
    expect(state.page.value.items).toHaveLength(q.limit);
    expect(request.mock.calls.at(-1)?.[0]).not.toContain('cursor=');
  });
  it('非游标原因的 400 不重试，直接显示错误', async () => {
    request.mockRejectedValueOnce(new ApiError(400, 'invalid_watchlist', '请核对名单、规范值、探针范围和有效期'));
    const { state } = host(() => useWatchlistHits());
    state.load(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.pending.value).toBe(false));
    expect(request).toHaveBeenCalledTimes(1);
    expect(state.error.value).toBeTruthy();
  });
  it('窗口非法时不发起请求，直接给出可纠正提示', async () => {
    const { state } = host(() => useWatchlistHits());
    state.load(list, '2026-11-06T00:00:00Z', '2026-11-05T00:00:00Z');
    await flushPromises();
    expect(request).not.toHaveBeenCalled();
    expect(state.error.value).toContain('命中查询窗口');
    expect(state.loaded.value).toBe(false);
  });
  it('切换租户时取消读取并清空已有命中', async () => {
    request.mockResolvedValueOnce(await page());
    const { state } = host(() => useWatchlistHits());
    state.load(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.loaded.value).toBe(true));
    const late = deferred<unknown>();
    request.mockReturnValueOnce(late.promise);
    state.load(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await flushPromises();
    const signal = request.mock.lastCall?.[1].signal as AbortSignal;
    user.value = { ...principal, tenant_id: 't_other' };
    await flushPromises();
    expect(signal.aborted).toBe(true);
    expect(state.page.value.items).toEqual([]);
    expect(state.loaded.value).toBe(false);
    late.resolve(await page());
    await flushPromises();
    expect(state.page.value.items).toEqual([]);
  });
  it('迟到响应不覆盖当前内容', async () => {
    const late = deferred<unknown>();
    request.mockReturnValueOnce(late.promise);
    const { state } = host(() => useWatchlistHits());
    state.load(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await flushPromises();
    const fresh = await page({ items: [await hit({ event_id: 'evt_3' })] });
    request.mockResolvedValueOnce(fresh);
    state.load(list, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.loaded.value).toBe(true));
    late.resolve(await page());
    await flushPromises();
    expect(state.page.value.items[0]!.event_id).toBe('evt_3');
  });
});

describe('历史影响 composable', () => {
  it('仅管理员可发起预览', async () => {
    user.value = { ...principal, role: 'viewer' };
    const { state } = host(() => useWatchlistImpact());
    await state.run(list, 3, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    expect(request).not.toHaveBeenCalled();
    expect(state.result.value).toBeNull();
  });
  it('服务端报告检索不完整时标记 incomplete 且不交付结果', async () => {
    request.mockRejectedValueOnce(
      new ApiError(503, 'watchlist_impact_incomplete', '历史告警检索结果不完整，本次未交付计数'),
    );
    const { state } = host(() => useWatchlistImpact());
    await state.run(list, 3, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.pending.value).toBe(false));
    expect(state.incomplete.value).toBe(true);
    expect(state.result.value).toBeNull();
    expect(state.error.value).toContain('不完整');
  });
  it('成功预览交付结果并清除不完整标记', async () => {
    request.mockResolvedValueOnce(impact());
    const { state } = host(() => useWatchlistImpact());
    await state.run(list, 3, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.pending.value).toBe(false));
    expect(state.incomplete.value).toBe(false);
    expect(state.result.value?.total).toBe(1);
    expect(request.mock.lastCall?.[0]).toBe(`/watchlists/${list}/impact`);
    expect(request.mock.lastCall?.[1].method).toBe('POST');
    expect(request.mock.lastCall?.[1].body).toEqual({
      revision: 3,
      start: '2026-11-05T00:00:00Z',
      end: '2026-11-06T00:00:00Z',
    });
  });
  it('额度用尽返回 429 时提示稍后重试，不混入服务不可用也不标记检索不完整', async () => {
    request.mockRejectedValueOnce(new ApiError(429, 'watchlist_quota', '名单、近期变更或预览数量已达上限'));
    const { state } = host(() => useWatchlistImpact());
    await state.run(list, 3, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.pending.value).toBe(false));
    expect(state.incomplete.value).toBe(false);
    expect(state.result.value).toBeNull();
    expect(state.error.value).toContain('预览额度已用尽');
    expect(state.error.value).not.toContain('不可用');
    expect(state.error.value).not.toContain('不完整');
  });
  it('结果与本次核对范围不一致时不交付结果', async () => {
    request.mockResolvedValueOnce(impact({ list_revision: 2 }));
    const { state } = host(() => useWatchlistImpact());
    await state.run(list, 3, '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z');
    await vi.waitFor(() => expect(state.pending.value).toBe(false));
    expect(state.result.value).toBeNull();
    expect(state.error.value).toBeTruthy();
  });
});
