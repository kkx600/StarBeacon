import {webcrypto} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,flushPromises,mount} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import type {ApiClient} from '../packages/shared/src/api'
import type {PacketRecord} from '../packages/shared/src/packetArchives'
import {verifyPacketInspection,type PacketInspection} from '../packages/shared/src/packetInspection'
import Inspector from '../packages/shared/src/components/PacketInspector.vue'
import {click,button,deferred} from './fixtures'

const stamp='2026-10-03T01:00:00.123456789Z'
const record:PacketRecord={id:'packet_owned',state:'ready',manifest_sha256:'a'.repeat(64),capture:{id:'packet_owned',tenant_id:'tenant_owned',sensor_id:'probe_owned',registration_id:'reg_owned',run_id:'run_owned',interface:'eth0',interface_mac:'02:00:00:00:00:01',settings_sha256:'a'.repeat(64),bpf_filter:'',promiscuous:false,started_at:stamp,ended_at:'2026-10-03T01:00:02Z',first_packet_at:stamp,last_packet_at:'2026-10-03T01:00:01Z',packets:3,packet_bytes:200,truncated_packets:0,vlan_offload_packets:0,kernel_drops:'0',counter_state:'observed',termination:'rotation',format:'pcapng',source:'AF_PACKET',snap_length:262144},created_at:stamp}
const bytes=new TextEncoder().encode('GET /starbeacon/validation HTTP/1.1\r\nHost: example.test\r\n\r\n')
let result:PacketInspection
beforeEach(async()=>{
 vi.stubGlobal('crypto',webcrypto)
 const sha=Buffer.from(await webcrypto.subtle.digest('SHA-256',bytes)).toString('hex')
 result={schema:'packet.inspect.v1',archive_id:record.id,manifest_sha256:record.manifest_sha256!,raw_sha256:'b'.repeat(64),packet_sha256:sha,number:1,total:3,captured_at:stamp,captured_length:bytes.length,original_length:bytes.length,truncated:false,interface:'eth0',vlan_offload:false,decode_status:'parsed',layers:[{name:'Ethernet',offset:0,length:14,fields:[{name:'eth.src',value:'02:00:00:00:00:01'},{name:'eth.dst',value:'02:00:00:00:00:02'}]},{name:'TCP',offset:14,length:20,fields:[{name:'tcp.flags.syn',value:'true'}]}],packet:Buffer.from(bytes).toString('base64'),checksum_validation:'not_checked',payload_visibility:'not_decoded'}
})
const clone=()=>structuredClone(result)
const scope=()=>new DOMWrapper(document.body)
const show=async(api:ApiClient,selected:PacketRecord|null=record)=>{const wrapper=mount(Inspector,{props:{api,record:selected},attachTo:document.body,global:{plugins:[registerAnt]}});await flushPromises();await vi.waitFor(()=>expect(scope().text()).toContain(selected?'协议层':''));return wrapper}

describe('原包协议回执核验',()=>{
 it('绑定归档、包序号、捕获纳秒时间和实际字节',async()=>{expect(await verifyPacketInspection(clone(),record,1)).toEqual(result)})
 it('拒绝错误身份、伪长度、捕获时段和协议字段',async()=>{
  const mutations:((r:PacketInspection)=>void)[]=[r=>r.archive_id='foreign',r=>r.manifest_sha256='c'.repeat(64),r=>r.number=2,r=>r.total=4,r=>r.captured_at='2026-10-03T01:00:00.123456788Z',r=>r.captured_at='invalid',r=>r.interface='eth1',r=>r.captured_length=262145,r=>r.original_length=0,r=>r.truncated=true,r=>r.packet_sha256='bad',r=>r.raw_sha256='bad',r=>r.checksum_validation='verified' as never,r=>r.payload_visibility='plaintext' as never,r=>r.decode_status='complete' as never,r=>r.layers=Array(17).fill(r.layers[0]),r=>r.layers[0]!.offset=bytes.length,r=>r.layers[0]!.name='\0',r=>r.layers[0]!.fields[0]!.name='invalid field',r=>r.layers[0]!.fields[0]!.value='\0',r=>r.layers[0]!.fields[0]!.value='a'.repeat(769),r=>r.packet='***',r=>r.packet='AAAA',r=>r.packet_sha256='d'.repeat(64)]
  for(const mutate of mutations){const r=clone();mutate(r);await expect(verifyPacketInspection(r,record,1)).rejects.toThrow('原包回执')}
  await expect(verifyPacketInspection(null,record,1)).rejects.toThrow('原包回执')
 })
 it('没有浏览器摘要能力时不给出未核验原字节',async()=>{vi.stubGlobal('crypto',{});await expect(verifyPacketInspection(result,record,1)).rejects.toThrow('HTTPS')})
 it('截断和未映射协议层保持独立状态',async()=>{const r=clone();r.original_length=bytes.length+20;r.truncated=true;r.decode_status='partial';r.layers[0]!.offset=null;expect((await verifyPacketInspection(r,record,1)).truncated).toBe(true)})
})

describe('原包协议查看交互',()=>{
 it('真实弹窗只有协议字段和原字节，保留纳秒时间与副本区别',async()=>{
  const request=vi.fn().mockResolvedValue(result),wrapper=await show({request} as unknown as ApiClient)
  expect(document.querySelectorAll('[role=dialog]').length).toBe(1)
  expect(document.querySelectorAll('.ant-table-wrapper').length).toBe(0)
  expect(scope().text()).toContain(stamp);expect(scope().text()).toContain('实际捕获字节');expect(scope().text()).not.toContain('EVE 导出副本')
  expect(request.mock.calls[0]![0]).toBe('/packet-archives/packet_owned/packets/1')
  expect(button('上一包').disabled).toBe(true)
  await click('UTF-8');expect(scope().text()).toContain('GET /starbeacon/validation')
  await click('下一包');await vi.waitFor(()=>expect(scope().text()).toContain('回执与所选归档'))
  expect(request).toHaveBeenCalledTimes(2)
  const close=document.querySelector<HTMLButtonElement>('.ant-modal-close')!;close.click();await flushPromises();expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('序号跳转与边界按钮读取当前包',async()=>{
  const request=vi.fn().mockImplementation((path:string)=>Promise.resolve({...result,number:Number(path.split('/').at(-1))}))
  await show({request} as unknown as ApiClient)
  const input=scope().get('input[role=spinbutton]');await input.setValue('3');await input.trigger('blur');await click('查看原包')
  await vi.waitFor(()=>{expect(button('下一包').disabled).toBe(true);expect(button('上一包').disabled).toBe(false)});expect(request.mock.calls.at(-1)![0]).toContain('/packets/3')
  await click('上一包');await vi.waitFor(()=>expect(request.mock.calls.at(-1)![0]).toContain('/packets/2'))
  await vi.waitFor(()=>expect(button('上一包').disabled).toBe(false));const calls=request.mock.calls.length;await input.setValue('');expect(button('查看原包').disabled).toBe(true);await input.trigger('blur');await flushPromises();expect(button('查看原包').disabled).toBe(true);expect(request).toHaveBeenCalledTimes(calls)
 })
 it('请求失败可重试，并且清除上一包内容',async()=>{
  const request=vi.fn().mockRejectedValueOnce(new Error('存储不可用')).mockResolvedValue(result)
  const wrapper=mount(Inspector,{props:{api:{request} as unknown as ApiClient,record},attachTo:document.body,global:{plugins:[registerAnt]}})
  await vi.waitFor(()=>expect(scope().text()).toContain('存储不可用'))
  expect(scope().text()).not.toContain('协议层');await click('重试');await vi.waitFor(()=>expect(scope().text()).toContain('协议层'));wrapper.unmount()
 })
 it('关闭和切换对象取消请求，迟到结果不能复活字节',async()=>{
  const pending=deferred<PacketInspection>(),request=vi.fn().mockReturnValue(pending.promise)
  const wrapper=mount(Inspector,{props:{api:{request} as unknown as ApiClient,record},attachTo:document.body,global:{plugins:[registerAnt]}})
  await flushPromises();const signal=request.mock.calls[0]![1].signal as AbortSignal
  await wrapper.setProps({record:null});expect(signal.aborted).toBe(true);pending.resolve(result);await flushPromises();expect(scope().text()).not.toContain('协议层')
 })
 it('部分解析、截断和 VLAN 卸载不能显示为完整原件',async()=>{
  const r=clone();r.original_length=bytes.length+20;r.truncated=true;r.vlan_offload=true;r.decode_status='partial'
  await show({request:vi.fn().mockResolvedValue(r)} as unknown as ApiClient)
  expect(scope().text()).toContain('部分头部无法解析');expect(scope().text()).toContain('捕获内容被截断');expect(scope().text()).toContain('未向原字节补写标签')
 })
})
