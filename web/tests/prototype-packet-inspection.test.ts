import {webcrypto} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,flushPromises,mount} from '@vue/test-utils'
import {createMemoryHistory,createRouter} from 'vue-router'
import {registerAnt} from '../packages/shared/src/ant'
import Inspector from '../packages/shared/src/components/PacketInspector.vue'
import PrototypeInspector from '../../prototype/src/components/PacketInspectionDialog.vue'
import {PacketExampleClient,packetExampleLayers,packetExampleRecord} from '../../prototype/src/data/packetInspectionPreview'
import {packetPreviewLocation} from '../../prototype/src/composables/packetPreview'
import {verifyPacketInspection} from '../packages/shared/src/packetInspection'
import {button,click} from './fixtures'

const scope=()=>new DOMWrapper(document.body)
const location=(inspection='data')=>packetPreviewLocation({inspect:'packet',inspection},packetExampleLayers)
beforeEach(()=>{vi.stubGlobal('crypto',webcrypto);vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new Error('原型不得访问网络')))})
async function preview(query='inspect=packet&packet=1&layer=1&inspection=data'){
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/archives',component:{template:'<div />'}}]})
 await router.push('/archives?state=data&filter=tcp&'+query+'#evidence');await router.isReady()
 const wrapper=mount(PrototypeInspector,{props:{open:true,record:{id:'PACKET-0001',name:'合成归档',status:'已归档'}},attachTo:document.body,global:{plugins:[registerAnt,router]}})
 await flushPromises()
 return {wrapper,router}
}

describe('原包样本隔离',()=>{
 it('九帧固定字节通过工程摘要核验，所有非法请求都不访问网络',async()=>{
  const client=new PacketExampleClient(()=>location())
  for(let number=1;number<=9;number++){
   const raw=await client.request('/packet-archives/packet_example/packets/'+number)
   expect((await verifyPacketInspection(raw,packetExampleRecord,number)).number).toBe(number)
  }
  for(const path of ['/auth/me','https://external.test','/packet-archives/foreign/packets/1','/packet-archives/packet_example/packets/01','/packet-archives/packet_example/packets/10'])await expect(client.request(path)).rejects.toThrow('固定合成样本')
  await expect(client.request('/packet-archives/packet_example/packets/1',{method:'POST'})).rejects.toThrow('固定合成样本')
  expect(fetch).not.toHaveBeenCalled()
 })
 it('加载中可取消，取消前后的请求均不转为实际HTTP请求',async()=>{
  const client=new PacketExampleClient(()=>location('loading')),controller=new AbortController()
  const pending=client.request('/packet-archives/packet_example/packets/1',{signal:controller.signal})
  controller.abort();await expect(pending).rejects.toMatchObject({name:'AbortError'})
  await expect(client.request('/packet-archives/packet_example/packets/1',{signal:controller.signal})).rejects.toMatchObject({name:'AbortError'})
  await expect(client.request('/packet-archives/packet_example/packets/1')).rejects.toThrow('可取消')
  expect(fetch).not.toHaveBeenCalled()
 })
})

describe('共享原包查看入口',()=>{
 it('默认入口保持第一包，指定起始包和协议层可用且同号更新不重发',async()=>{
  const client=new PacketExampleClient(()=>location()),request=vi.spyOn(client,'request')
  const wrapper=mount(Inspector,{props:{api:client,record:packetExampleRecord,initialNumber:4,initialLayer:3},attachTo:document.body,global:{plugins:[registerAnt]}})
  await vi.waitFor(()=>expect(scope().text()).toContain('协议层'))
  expect(request.mock.calls[0]![0]).toMatch(/\/packets\/4$/)
  expect(scope().find('.ant-collapse-item-active').text()).toContain('3. TCP')
  await wrapper.setProps({initialNumber:4});expect(request).toHaveBeenCalledTimes(1)
  await wrapper.setProps({initialNumber:9});await vi.waitFor(()=>expect(button('下一包').disabled).toBe(true));expect(request).toHaveBeenCalledTimes(2)
  await wrapper.setProps({initialLayer:null});expect(scope().findAll('.ant-collapse-item-active')).toHaveLength(0)
  expect(fetch).not.toHaveBeenCalled()
 })
 it.each([0,10,NaN])('无效起始包 %s 不读取任何内容',async initialNumber=>{
  const client=new PacketExampleClient(()=>location()),request=vi.spyOn(client,'request')
  mount(Inspector,{props:{api:client,record:packetExampleRecord,initialNumber},attachTo:document.body,global:{plugins:[registerAnt]}})
  await flushPromises();expect(scope().text()).toContain('包序号不在');expect(scope().find('.protocol-layers').exists()).toBe(false);expect(request).not.toHaveBeenCalled()
 })
})

describe('原型逐包查看与工程交互一致',()=>{
 it('深链打开指定包，合成来源明确，翻页保留业务条件和hash',async()=>{
  const {wrapper,router}=await preview('inspect=packet&packet=4&layer=3&inspection=data')
  await vi.waitFor(()=>expect(scope().text()).toContain('协议层'))
  expect(scope().text()).toContain('没有读取所选目录的实际原文')
  expect(scope().find('.ant-collapse-item-active').text()).toContain('3. TCP')
  expect(document.querySelectorAll('[role=dialog]')).toHaveLength(1)
  expect(document.querySelectorAll('.ant-table-wrapper')).toHaveLength(0)
  await click('下一包');await vi.waitFor(()=>expect(router.currentRoute.value.query.packet).toBe('5'))
  expect(router.currentRoute.value.query.filter).toBe('tcp');expect(router.currentRoute.value.hash).toBe('#evidence');expect(router.currentRoute.value.query.layer).toBe('1')
  document.querySelector<HTMLButtonElement>('.ant-modal-close')!.click();await flushPromises();expect(wrapper.emitted('close')).toHaveLength(1)
  expect(fetch).not.toHaveBeenCalled()
 })
 it.each([['error','合成读取失败示例'],['expired','合成到期示例'],['corrupt','字节摘要不一致']])('%s状态不保留上一包字节',async(mode,message)=>{
  const {router}=await preview()
  await vi.waitFor(()=>expect(scope().text()).toContain('协议层'))
  await router.replace({query:{...router.currentRoute.value.query,inspection:mode}})
  await vi.waitFor(()=>expect(scope().text()).toContain(message))
  expect(scope().find('.protocol-layers').exists()).toBe(false)
  expect(fetch).not.toHaveBeenCalled()
 })
 it('加载与空结果不暴露样本，切换来源后不会出现旧字节',async()=>{
  const calls=vi.spyOn(PacketExampleClient.prototype,'request'),{wrapper,router}=await preview('inspect=packet&inspection=loading')
  await flushPromises();expect(scope().text()).toContain('正在读取数据');expect(scope().find('.protocol-layers').exists()).toBe(false)
  const signal=calls.mock.calls[0]![1]!.signal!
  await router.replace({query:{...router.currentRoute.value.query,inspection:'empty'}})
  await vi.waitFor(()=>expect(scope().text()).toContain('所选归档没有可查看的原包'));expect(signal.aborted).toBe(true);expect(scope().find('.protocol-layers').exists()).toBe(false)
  await wrapper.setProps({open:false});await flushPromises();expect(fetch).not.toHaveBeenCalled()
 })
 it('非法深链和不可查看的目录显示输入错误，不能退成成功样本',async()=>{
  const {wrapper,router}=await preview('inspect=packet&packet=00')
  await vi.waitFor(()=>expect(scope().text()).toContain('规范整数'));expect(scope().find('.protocol-layers').exists()).toBe(false)
  await router.replace({query:{...router.currentRoute.value.query,packet:'1'}})
  await wrapper.setProps({selectionError:'所选合成目录不可查看'})
  await vi.waitFor(()=>expect(scope().text()).toContain('所选合成目录不可查看'));expect(scope().find('.protocol-layers').exists()).toBe(false)
 })
})
