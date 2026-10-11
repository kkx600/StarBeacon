import type {SampleOrigin} from '../types'

export type ImportKind='pcap'|'http_raw'
export function importError(file:File|undefined,kind:ImportKind):string{
  if(!file)return kind==='http_raw'?'请选择 HTTP Raw 文件':'请选择 PCAP 或 PCAPNG 文件'
  if(kind==='http_raw')return file.size<1||file.size>2*1024*1024?'HTTP Raw 文件大小必须为 1 字节至 2 MiB':''
  return file.size<24||file.size>100*1024*1024?'文件大小必须为 24 字节至 100 MiB':''
}
export function sampleOrigin(value:unknown):SampleOrigin|undefined{
  if(!value||typeof value!=='object'||Array.isArray(value))return undefined
  const origin=value as Record<string,unknown>
  return origin.kind==='http_raw'&&origin.synthetic===true&&origin.encoder==='http-raw-tcp/1'&&origin.segment_bytes===1460&&typeof origin.raw_sha256==='string'&&/^[a-f0-9]{64}$/.test(origin.raw_sha256)&&Number.isInteger(origin.raw_bytes)&&Number(origin.raw_bytes)>=1&&Number(origin.raw_bytes)<=2*1024*1024?origin as unknown as SampleOrigin:undefined
}
