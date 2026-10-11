import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,nextTick,shallowRef} from 'vue'
import {flushPromises,mount} from '@vue/test-utils'
import {useInventory} from '../platform/src/features/inventory/useInventory'
import {useAlerts} from '../platform/src/features/alerts/useAlerts'
import {useSensors} from '../platform/src/features/sensors/useSensors'
import {useCollector} from '../collector/src/features/network/useCollector'
import type {InventoryKind,InventoryRecord} from '../platform/src/features/inventory/inventory'
import type {Sensor} from '../packages/shared/src/types'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',()=>({session:{api:{request},current:{value:{role:'admin'}}}}))
vi.mock('../collector/src/session',()=>({session:{api:{request},current:{value:{role:'admin'}}}}))
beforeEach(()=>{request.mockReset()})

function host<T>(factory:()=>T){let state!:T;const wrapper=mount(defineComponent({setup(){state=factory();return()=>h('div')}}));return {state,wrapper}}
function deferred<T>(){let resolve!:(value:T)=>void,reject!:(error:unknown)=>void;const promise=new Promise<T>((yes,no)=>{resolve=yes;reject=no});return {promise,resolve,reject}}
const record:InventoryRecord={id:'obj_1',kind:'groups',revision:1,data:{name:'办公区',owner:'网络团队',description:'',active:true},created_at:'2026-10-01T00:00:00Z',updated_at:'2026-10-01T00:00:00Z'}
const sensor:Sensor={id:'sensor_1',name:'办公区探针',registration_id:'reg_1',active:true,status:'online',created_at:'2026-10-01T00:00:00Z',last_seen:null,health:{}}

describe('资产管理请求和修订',()=>{
  it('按游标翻页、返回、搜索和刷新，切换对象时重置条件',async()=>{
    request.mockResolvedValue({items:[record],next_cursor:'obj_1'})
    const kind=shallowRef<InventoryKind>('groups'),{state}=host(()=>useInventory(kind));await flushPromises()
    expect(state.result.value.items).toEqual([record]);expect(state.pending.value).toBe(false)
    state.next();await flushPromises();expect(request.mock.lastCall?.[0]).toContain('cursor=obj_1');expect(state.cursors.value.length).toBe(2)
    state.previous();await flushPromises();expect(state.cursors.value).toEqual([''])
    state.previous();expect(state.cursors.value).toEqual([''])
    state.search('办公 %');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('keyword=%E5%8A%9E%E5%85%AC+%25')
    state.refresh();await flushPromises();expect(state.result.value.items.length).toBe(1)
    kind.value='networks';await flushPromises();expect(request.mock.lastCall?.[0]).toBe('/inventory/networks?cursor=&keyword=&limit=20');expect(state.cursors.value).toEqual([''])
  })
  it('新查询取消旧查询，迟到的数据和错误不覆盖当前列表',async()=>{
    const old=deferred<unknown>();request.mockReturnValueOnce(old.promise).mockResolvedValue({items:[],next_cursor:''})
    const {state,wrapper}=host(()=>useInventory(shallowRef<InventoryKind>('assets'))),signal=request.mock.calls[0]?.[1].signal as AbortSignal
    state.next();expect(state.cursors.value).toEqual([''])
    state.search('当前');await flushPromises();expect(signal.aborted).toBe(true)
    old.resolve({items:[record],next_cursor:'obsolete'});await flushPromises();expect(state.result.value.items).toEqual([]);expect(state.error.value).toBe('')
    const live=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(live.aborted).toBe(true)
  })
  it('保存携带预期修订，冲突保持草稿并允许重试',async()=>{
    request.mockResolvedValue({items:[],next_cursor:''});const {state}=host(()=>useInventory(shallowRef<InventoryKind>('groups')));await flushPromises()
    request.mockRejectedValueOnce(new Error('修订冲突'));expect(await state.save(record.data,record)).toBe(false);expect(state.saveError.value).toBe('修订冲突');expect(state.saving.value).toBe(false)
    state.clearSaveError();expect(state.saveError.value).toBe('')
    request.mockResolvedValueOnce(record);expect(await state.save(record.data,record)).toBe(true);expect(request.mock.calls.find(call=>call[1]?.method==='POST')?.[1].body).toMatchObject({id:'obj_1',expected_revision:1})
    await flushPromises()
    request.mockResolvedValueOnce(record);expect(await state.save(record.data,null)).toBe(true);await flushPromises()
    expect(request.mock.calls.filter(call=>call[1]?.method==='POST').at(-1)?.[1].body).toMatchObject({id:'',expected_revision:0})
  })
  it('阻止并发保存，切换对象取消保存且不关闭新的编辑状态',async()=>{
    request.mockResolvedValue({items:[],next_cursor:''});const kind=shallowRef<InventoryKind>('groups'),{state}=host(()=>useInventory(kind));await flushPromises()
    const saving=deferred<unknown>();request.mockReturnValueOnce(saving.promise);const first=state.save(record.data,record);expect(await state.save(record.data,record)).toBe(false)
    const signal=request.mock.lastCall?.[1].signal as AbortSignal;kind.value='assets';await nextTick();expect(signal.aborted).toBe(true);expect(state.saving.value).toBe(false)
    saving.resolve(record);expect(await first).toBe(false);expect(state.saveError.value).toBe('')
  })
  it('列表和保存的非标准错误均有可读提示',async()=>{
    request.mockRejectedValue('offline');const {state}=host(()=>useInventory(shallowRef<InventoryKind>('groups')));await flushPromises();expect(state.error.value).toBe('对象列表读取失败')
    expect(await state.save(record.data,record)).toBe(false);expect(state.saveError.value).toBe('对象保存失败')
  })
})

describe('告警查询窗口',()=>{
  it('新检索重置分页，刷新保持时间范围和过滤条件',async()=>{
    vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-02T00:00:00Z'));request.mockResolvedValue({items:[],total:0,page:1,page_size:20})
    const {state}=host(useAlerts);await flushPromises();expect(request.mock.lastCall?.[1].body.start).toBe('2026-10-01T00:00:00.000Z')
    state.search({source_ip:'192.0.2.1',filter:'tcp',destination_ip:'',method:'',path:'',keyword:'',protocol:'',severity:''},168);await flushPromises();expect(request.mock.lastCall?.[1].body).toMatchObject({page:1,filter:'tcp',source_ip:'192.0.2.1',start:'2026-09-25T00:00:00.000Z'})
    state.page(3,50);await flushPromises();expect(request.mock.lastCall?.[1].body).toMatchObject({page:3,page_size:50})
    vi.setSystemTime(new Date('2026-10-02T01:00:00Z'));state.refresh();await flushPromises();expect(request.mock.lastCall?.[1].body).toMatchObject({page:1,page_size:50,filter:'tcp',start:'2026-09-25T01:00:00.000Z'})
  })
  it('取消、错误和离开页面均不泄漏旧结果',async()=>{
    const old=deferred<unknown>();request.mockReturnValueOnce(old.promise).mockRejectedValueOnce(new Error('查询超时')).mockRejectedValueOnce('offline')
    const {state,wrapper}=host(useAlerts),signal=request.mock.lastCall?.[1].signal as AbortSignal;state.refresh();await flushPromises();expect(signal.aborted).toBe(true);expect(state.error.value).toBe('查询超时')
    old.reject(new Error('旧请求错误'));await flushPromises();expect(state.error.value).toBe('查询超时')
    state.refresh();await flushPromises();expect(state.error.value).toBe('检索失败');expect(state.pending.value).toBe(false)
    const live=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(live.aborted).toBe(true)
  })
})

describe('探针状态管理',()=>{
  it('读取、刷新和切换状态成功后回读，失败时保留错误',async()=>{
    request.mockResolvedValue({items:[sensor]});const {state}=host(useSensors);await flushPromises();expect(state.items.value).toEqual([sensor])
    expect(await state.toggle(sensor)).toBe(true);expect(request.mock.calls.find(call=>call[1]?.method==='PATCH')?.[1].body).toEqual({active:false})
    request.mockRejectedValueOnce(new Error('权限不足'));await expect(state.toggle(sensor)).rejects.toThrow('权限不足');expect(state.saving.value).toBe(false)
    request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('读取失败')
  })
  it('取消旧刷新并拒绝离开后的状态写入',async()=>{
    const old=deferred<unknown>();request.mockReturnValueOnce(old.promise).mockResolvedValue({items:[]});const {state,wrapper}=host(useSensors),signal=request.mock.lastCall?.[1].signal as AbortSignal
    await state.refresh();expect(signal.aborted).toBe(true);old.resolve({items:[sensor]});await flushPromises();expect(state.items.value).toEqual([])
    const saving=deferred<unknown>();request.mockReturnValueOnce(saving.promise);const first=state.toggle(sensor);expect(await state.toggle(sensor)).toBe(false);const writeSignal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(writeSignal.aborted).toBe(true);saving.resolve({ok:true});expect(await first).toBe(false);expect(await state.toggle(sensor)).toBe(false)
  })
})

describe('采集器网络配置',()=>{
  const capture={interfaces:['eth0'],status:'pending_apply'}
  function respond(path:string){return Promise.resolve(path==='/health'?{version:'test'}:path==='/network/interfaces'?{items:[{name:'eth0'}]}:capture)}
  it('聚合实际接口与状态，保存后展示回读的应用状态',async()=>{
    request.mockImplementation(respond);const {state}=host(useCollector);await flushPromises();expect(state.health.value).toMatchObject({version:'test'});expect(state.interfaces.value).toEqual([{name:'eth0'}]);expect(state.capture.value).toEqual(capture)
    expect(await state.save(['eth0'])).toBe(true);expect(request.mock.lastCall?.[1].body).toEqual({interfaces:['eth0']});expect(state.saving.value).toBe(false)
    request.mockRejectedValueOnce(new Error('接口不存在'));await expect(state.save(['deleted'])).rejects.toThrow('接口不存在');expect(state.capture.value).toEqual(capture)
    request.mockRejectedValue(new Error('连接失败'));await state.refresh();expect(state.error.value).toBe('连接失败');request.mockRejectedValue('offline');await state.refresh();expect(state.error.value).toBe('读取失败')
  })
  it('离开页面取消查询和写请求，不能报告迟到保存成功',async()=>{
    const old=deferred<unknown>();request.mockReturnValueOnce(old.promise).mockImplementation(respond);const {state,wrapper}=host(useCollector),signal=request.mock.calls[0]?.[1].signal as AbortSignal;await state.refresh();old.resolve({version:'obsolete'});await flushPromises();expect(signal.aborted).toBe(true);expect(state.health.value).toMatchObject({version:'test'})
    const saving=deferred<unknown>();request.mockReturnValueOnce(saving.promise);const first=state.save(['eth0']);expect(await state.save(['eth0'])).toBe(false);const writeSignal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(writeSignal.aborted).toBe(true);saving.resolve(capture);expect(await first).toBe(false);expect(await state.save(['eth0'])).toBe(false)
  })
})
