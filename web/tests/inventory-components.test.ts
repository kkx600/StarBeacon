import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import InventoryTable from '../platform/src/features/inventory/InventoryTable.vue'
import InventoryForm from '../platform/src/features/inventory/InventoryForm.vue'
import InventoryDetail from '../platform/src/features/inventory/InventoryDetail.vue'
import GroupSelector from '../platform/src/features/inventory/GroupSelector.vue'
import {createDraft,details,type InventoryRecord} from '../platform/src/features/inventory/inventory'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',()=>({session:{api:{request}}}))
beforeEach(()=>{request.mockReset();request.mockResolvedValue({items:[],next_cursor:''})})
const global={plugins:[registerAnt]}
const group:InventoryRecord={id:'group_1',kind:'groups',revision:3,data:{name:'集团办公区',owner:'网络团队',description:'确认的归属',active:true},created_at:'2026-10-01T00:00:00Z',updated_at:'2026-10-02T00:00:00Z'}
const asset:InventoryRecord={...group,id:'asset_1',kind:'assets',data:{name:'办公服务器',description:'',active:true,owner:'',criticality:'critical',network_domain:'office',interfaces:[{name:'eth0',mac:'02:00:00:00:00:01',ips:['192.0.2.1','2001:db8::1']}]}}
const network:InventoryRecord={...group,id:'network_1',kind:'networks',data:{name:'办公网段',prefix:'192.0.2.0/24',purpose:'internal',network_domain:'office',description:'',active:false}}
function findButton(label:string){const button=Array.from(document.body.querySelectorAll<HTMLButtonElement>('button')).find(value=>value.textContent?.replace(/\s/g,'')===label);expect(button,`页面应提供 ${label}`).toBeDefined();return button!}
async function click(label:string){findButton(label).click();await flushPromises()}
async function input(selector:string,value:string){const field=document.body.querySelector<HTMLInputElement|HTMLTextAreaElement>(selector);expect(field).not.toBeNull();field!.value=value;field!.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('资产类型与记录摘要',()=>{
  it('默认配置按对象类型生成，编辑草稿不改动原始记录',()=>{
    expect(createDraft('groups')).toMatchObject({owner:'',active:true});expect(createDraft('assets')).toMatchObject({criticality:'normal',interfaces:[]});expect(createDraft('networks')).toMatchObject({purpose:'internal',network_domain:'default'})
    const draft=createDraft('assets',asset.data);draft.interfaces![0]!.ips.push('192.0.2.2');expect(asset.data.interfaces?.[0]?.ips).toHaveLength(2)
    expect(details(asset)).toEqual(expect.arrayContaining([{label:'重要性',value:'关键'},{label:'责任人',value:'未指定'}]));expect(details(network)).toEqual(expect.arrayContaining([{label:'用途',value:'内部网络'}]));expect(details(group)).toEqual(expect.arrayContaining([{label:'修订',value:'3'}]))
    expect(details({...asset,data:{name:'空资产',active:false,description:''}})).toEqual(expect.arrayContaining([{label:'网络接口',value:'未配置网络接口'},{label:'重要性',value:'未指定'}]))
    expect(details({...network,data:{name:'空网段',active:true,description:''}})).toEqual(expect.arrayContaining([{label:'用途',value:'未指定'},{label:'网段',value:'未配置'}]))
  })
  it('单一表格按类型显示内容，查看与编辑遵守权限',async()=>{
    const wrapper=mount(InventoryTable,{props:{kind:'assets',records:[asset],editable:true},global});expect(wrapper.text()).toContain('eth0');expect(wrapper.text()).toContain('2001:db8::1');expect(wrapper.text()).toContain('关键')
    await wrapper.findAll('button').find(value=>value.text()==='编辑')!.trigger('click');expect(wrapper.emitted('edit')?.[0]?.[0]).toEqual(asset)
    await wrapper.findAll('button').find(value=>value.text()==='办公服务器')!.trigger('click');expect(wrapper.emitted('view')?.[0]?.[0]).toEqual(asset)
    await wrapper.setProps({kind:'groups',records:[{...group,data:{...group.data,owner:''}}],editable:false});expect(wrapper.text()).toContain('未指定');expect(wrapper.findAll('button').some(button=>button.text()==='编辑')).toBe(false)
    await wrapper.setProps({kind:'networks',records:[network]});expect(wrapper.text()).toContain('192.0.2.0/24');expect(wrapper.text()).toContain('已停用')
    await wrapper.setProps({kind:'assets',records:[{...asset,data:{...asset.data,criticality:'future',interfaces:[]}}]});expect(wrapper.text()).toContain('未配置');expect(wrapper.text()).toContain('未指定')
  })
})

describe('资产编辑表单',()=>{
  it('创建和编辑校验名称，失败保留草稿，提交使用稳定对象标识',async()=>{
    const wrapper=mount(InventoryForm,{props:{kind:'groups',record:null,pending:false,error:''},global,attachTo:document.body});await flushPromises();await click('保存');expect(wrapper.emitted('save')).toBeUndefined();await vi.waitFor(()=>expect(document.body.textContent).toContain('请输入名称'))
    await input('input[id$="name"]','新的办公区');await click('保存');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));const [data,id]=wrapper.emitted('save')![0]!;expect(data).toMatchObject({name:'新的办公区',active:true});expect(id).toMatch(/^obj_[a-f0-9]{32}$/)
    await wrapper.setProps({error:'修订冲突，请核对当前内容'});expect(document.body.textContent).toContain('修订冲突');expect(document.body.querySelector<HTMLInputElement>('input[id$="name"]')!.value).toBe('新的办公区')
    await click('保存');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(2));expect(wrapper.emitted('save')![1]![1]).toBe(id)
    await wrapper.setProps({pending:true});expect(document.body.querySelector<HTMLInputElement>('input[id$="name"]')?.disabled).toBe(true);expect(findButton('取消').disabled).toBe(true)
    await wrapper.setProps({pending:false});await click('取消');expect(wrapper.emitted('close')).toHaveLength(1)
  })
  it('动态接口支持 MAC 和双栈地址，移除接口不串改剩余数据',async()=>{
    const wrapper=mount(InventoryForm,{props:{kind:'assets',record:asset,pending:false,error:''},global,attachTo:document.body});await flushPromises();await click('添加接口');expect(document.body.querySelectorAll('.interface-fields')).toHaveLength(2)
    const rows=document.body.querySelectorAll('.interface-fields');const name=rows[1]!.querySelector<HTMLInputElement>('input')!;name.value='eth1';name.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()
    const ips=rows[1]!.querySelector<HTMLTextAreaElement>('textarea')!;ips.value='198.51.100.2, 2001:db8::2';ips.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()
    const controlIds=Array.from(rows[1]!.querySelectorAll<HTMLInputElement|HTMLTextAreaElement>('input,textarea'),field=>field.id);expect(controlIds.every(Boolean)).toBe(true)
    for(const label of document.body.querySelectorAll<HTMLLabelElement>('.ant-form-item-label label')){expect(label.htmlFor,`字段 ${label.textContent} 应关联输入控件`).not.toBe('');expect(document.getElementById(label.htmlFor)).not.toBeNull()}
    ;(rows[0]!.querySelector('button') as HTMLButtonElement).click();await flushPromises();await click('保存');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));expect(wrapper.emitted('save')![0]![0]).toMatchObject({interfaces:[{name:'eth1',ips:['198.51.100.2','2001:db8::2']}]});expect(wrapper.emitted('save')![0]![1]).toBe(asset.id);expect(asset.data.interfaces?.[0]?.name).toBe('eth0')
    expect(Array.from(document.body.querySelectorAll<HTMLInputElement|HTMLTextAreaElement>('.interface-fields input,.interface-fields textarea'),field=>field.id)).toEqual(controlIds)
  })
  it('网段配置要求网络域和 CIDR，表单展示用途及启停状态',async()=>{
    const wrapper=mount(InventoryForm,{props:{kind:'networks',record:network,pending:false,error:''},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain('内部网络');expect(document.body.textContent).toContain('停用');await click('保存');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));expect(wrapper.emitted('save')![0]![0]).toMatchObject({prefix:'192.0.2.0/24',network_domain:'office',purpose:'internal',active:false})
  })
})

describe('资产组查询和历史修订',()=>{
  it('按名称查询并保留已选资产组，不重复列出选项',async()=>{
    request.mockImplementation((path:string)=>Promise.resolve(path.includes('group_1')?group:{items:[group],next_cursor:''}));const wrapper=mount(GroupSelector,{props:{modelValue:group.id,disabled:false,inputId:'inventory-group'},global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain(group.data.name);expect(wrapper.get('input').attributes('id')).toBe('inventory-group');await vi.waitFor(()=>expect(request.mock.calls.some(call=>String(call[0]).includes('keyword='))).toBe(true))
    const input=wrapper.get('input');await input.setValue('集团');await vi.waitFor(()=>expect(request.mock.lastCall?.[0]).toContain('keyword=%E9%9B%86%E5%9B%A2'));await wrapper.setProps({modelValue:''});expect(wrapper.text()).not.toContain(group.data.name)
    const signals=request.mock.calls.map(call=>call[1]?.signal as AbortSignal);wrapper.unmount();expect(signals.at(-1)?.aborted).toBe(true)
  })
  it('读取失败可重试，关联对象错误和目录错误独立处理',async()=>{
    request.mockRejectedValue(new Error('资产组不可访问'));const wrapper=mount(GroupSelector,{props:{modelValue:group.id,disabled:false},global,attachTo:document.body});await flushPromises();await vi.waitFor(()=>expect(wrapper.text()).toContain('资产组不可访问'))
    request.mockResolvedValue({items:[],next_cursor:''});await wrapper.get('button').trigger('click');await vi.waitFor(()=>expect(request.mock.lastCall?.[0]).toContain('/inventory/groups?'));await flushPromises();expect(wrapper.text()).toContain('资产组不可访问')
    await wrapper.setProps({modelValue:''});expect(wrapper.text()).not.toContain('资产组不可访问')
  })
  it('历史读取失败保留当前记录，重试后可核对修订且关闭取消请求',async()=>{
    request.mockRejectedValueOnce(new Error('历史读取超时')).mockResolvedValueOnce({items:[group,{...group,revision:2,data:{...group.data,name:'历史办公区'}}]});const wrapper=mount(InventoryDetail,{props:{record:group},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain('历史读取超时');expect(document.body.textContent).toContain(group.data.name)
    await click('重试');await flushPromises();expect(document.body.textContent).not.toContain('历史读取超时');expect(document.body.textContent).toContain('180 天');expect(document.body.textContent).toContain(group.id)
    const signal=request.mock.lastCall?.[1].signal as AbortSignal;await wrapper.setProps({record:null});expect(signal.aborted).toBe(true)
  })
})
