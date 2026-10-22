import example from './packetInspectionExample.json' with {type:'json'}
import {ApiClient,ApiError} from '../../../web/packages/shared/src/api'
import type {PacketCapture,PacketRecord} from '../../../web/packages/shared/src/packetArchives'
import type {PacketInspection} from '../../../web/packages/shared/src/packetInspection'
import type {PacketPreviewLocation} from '../composables/packetPreview'

const packets=example.packets as PacketInspection[]
export const packetExampleLayers=Object.freeze(packets.map(packet=>packet.layers.length))
const first=packets[0]!,last=packets[packets.length-1]!
const capture:PacketCapture={
 id:first.archive_id,tenant_id:'tenant_example',sensor_id:'probe_example',registration_id:'reg_example',run_id:'run_example',
 interface:first.interface,interface_mac:'02:00:00:00:00:01',settings_sha256:'a'.repeat(64),bpf_filter:'',promiscuous:false,
 started_at:first.captured_at,ended_at:last.captured_at,first_packet_at:first.captured_at,last_packet_at:last.captured_at,
 packets:packets.length,packet_bytes:packets.reduce((sum,packet)=>sum+packet.captured_length,0),truncated_packets:0,vlan_offload_packets:0,
 kernel_drops:null,counter_state:'unavailable',termination:'rotation',format:'pcapng',source:'AF_PACKET',snap_length:262144,
}
export const packetExampleRecord:PacketRecord=Object.freeze({id:first.archive_id,state:'ready',capture:Object.freeze(capture),manifest_sha256:first.manifest_sha256,created_at:first.captured_at})
export const emptyPacketExampleRecord:PacketRecord=Object.freeze({...packetExampleRecord,capture:Object.freeze({...capture,packets:0,packet_bytes:0,first_packet_at:null,last_packet_at:null})})
const aborted=()=>new DOMException('合成原包查看已取消','AbortError')

// 仅提供固定字节样本给工程组件，不继承任何网络请求路径或真实认证行为。
export class PacketExampleClient extends ApiClient {
 constructor(private readonly location:()=>PacketPreviewLocation){super('/__prototype__/packet-inspection')}
 override async request<T>(path:string,options:Parameters<ApiClient['request']>[1]={}):Promise<T>{
  if(options?.signal?.aborted)throw aborted()
  const match=/^\/packet-archives\/packet_example\/packets\/([1-9][0-9]*)$/.exec(path)
  const index=match?Number(match[1]):0
  if(!match||index<1||index>packets.length||options?.method&&options.method!=='GET'||options?.body!==undefined||options?.file!==undefined)throw new ApiError(400,'example_request_invalid','原型仅允许读取固定合成样本')
  const state=this.location()
  if(state.error)throw new ApiError(400,'example_input_invalid',state.error)
  if(state.mode==='loading'){
   const signal=options?.signal
   if(!signal)throw new ApiError(400,'example_cancel_required','加载示例需要可取消的读取请求')
   return new Promise<T>((_resolve,reject)=>signal.addEventListener('abort',()=>reject(aborted()),{once:true}))
  }
  if(state.mode==='error')throw new ApiError(503,'example_source_unavailable','合成读取失败示例：原包存储暂时不可用，请核对来源后重试')
  if(state.mode==='expired')throw new ApiError(410,'example_archive_expired','合成到期示例：归档已超过保留期限，不再返回通信原文')
  const response=structuredClone(packets[index-1]!)
  if(state.mode==='corrupt')response.packet_sha256='0'.repeat(64)
  if(options?.signal?.aborted)throw aborted()
  return response as T
 }
}
