export type ByteEvidence = {state:'available';kind:'packet'|'payload';bytes:Uint8Array}|{state:'missing'|'invalid';message:string}

export function eveBytes(original:string):ByteEvidence {
  if(!original) return {state:'missing',message:'当前记录未提供原始载荷读取权限或字节证据'}
  let value:Record<string,unknown>
  try {const parsed:unknown=JSON.parse(original);if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error();value=parsed as Record<string,unknown>}
  catch {return {state:'invalid',message:'原始 EVE 无法解析，不能提取字节证据'}}
  const kind=value.packet==null?'payload':'packet', raw=value[kind]
  if(raw==null || raw==='')return {state:'missing',message:'检测引擎未随事件导出数据包或应用载荷，需查看关联 PCAP'}
  if(typeof raw!=='string'||raw.length>1398104||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(raw))return {state:'invalid',message:'字节证据编码无效或超过 1 MiB 展示上限'}
  try {const decoded=atob(raw);if(decoded.length>1024*1024)return {state:'invalid',message:'字节证据编码无效或超过 1 MiB 展示上限'};return {state:'available',kind,bytes:Uint8Array.from(decoded,char=>char.charCodeAt(0))}}
  catch {return {state:'invalid',message:'字节证据无法解码'}}
}
export function hexRows(bytes:Uint8Array, start=0, limit=256):string {
  const offset=Math.max(0,Math.floor(start)), end=Math.min(bytes.length,offset+Math.max(0,Math.min(4096,Math.floor(limit))))
  const rows:string[]=[]
  for(let index=offset;index<end;index+=16) {
    const row=bytes.subarray(index,Math.min(index+16,end))
    const hex=Array.from(row,byte=>byte.toString(16).padStart(2,'0')).join(' ').padEnd(47,' ')
    const text=Array.from(row,byte=>byte>=32&&byte<=126?String.fromCharCode(byte):'.').join('')
    rows.push(`${index.toString(16).padStart(8,'0')}  ${hex}  |${text}|`)
  }
  return rows.join('\n')
}
export function decodeUTF8(bytes:Uint8Array):{valid:boolean;text:string} {
  try {return {valid:true,text:new TextDecoder('utf-8',{fatal:true}).decode(bytes)}}
  catch {return {valid:false,text:''}}
}

export type ByteRange = {offset:number;length:number}
export type ByteSearch = {offsets:number[];limited:boolean}
export type HexFragment = {text:string;matched:boolean}

export function byteNeedle(value:string,kind:'hex'|'utf8'):Uint8Array {
  if(!value || value.length>4096)throw new Error('请输入不超过 512 B 的查找内容')
  let result:Uint8Array
  if(kind==='hex') {
    const raw=value.trim()
    const tokens=/^(?:[0-9a-fA-F]{2})+$/.test(raw)?raw.match(/../g)!:raw.split(/(?:\s*:\s*|\s+)/)
    if(!tokens.length || tokens.some(token=>!/^[0-9a-fA-F]{2}$/.test(token)))throw new Error('HEX 需为完整字节，可连续输入或用空格、冒号分隔')
    result=Uint8Array.from(tokens,token=>parseInt(token,16))
  } else {
    // 不以替换字符搜索非法代理项，也不对证据做大小写或 Unicode 归一化。
    for(const character of value) {const point=character.codePointAt(0)!;if(point>=0xd800&&point<=0xdfff)throw new Error('查找文本包含无效 Unicode 字符')}
    result=new TextEncoder().encode(value)
  }
  if(!result.length || result.length>512)throw new Error('查找内容需为 1–512 B')
  return result
}

export function findBytes(bytes:Uint8Array,needle:Uint8Array):ByteSearch {
  if(bytes.length>1024*1024 || !needle.length || needle.length>512)throw new Error('字节查找范围超出限制')
  const offsets:number[]=[],prefix=new Uint16Array(needle.length)
  // 前缀表保证重复载荷仍按线性时间查找，保留重叠匹配并限制结果内存。
  for(let index=1,length=0;index<needle.length;index++) {
    while(length>0&&needle[index]!==needle[length])length=prefix[length-1]!
    if(needle[index]===needle[length])length++
    prefix[index]=length
  }
  for(let index=0,length=0;index<bytes.length;index++) {
    while(length>0&&bytes[index]!==needle[length])length=prefix[length-1]!
    if(bytes[index]===needle[length])length++
    if(length===needle.length) {
      if(offsets.length===1000)return {offsets,limited:true}
      offsets.push(index-needle.length+1)
      length=prefix[length-1]!
    }
  }
  return {offsets,limited:false}
}

export function highlightedHex(bytes:Uint8Array,start:number,range?:ByteRange):HexFragment[] {
  start=Number.isFinite(start)?Math.max(0,Math.floor(start)):0
  const raw=hexRows(bytes,start,256)
  if(!range || !Number.isInteger(range.offset) || !Number.isInteger(range.length) || range.offset<0 || range.length<1)return [{text:raw,matched:false}]
  const rows=raw.split('\n'),result:HexFragment[]=[]
  for(let index=0;index<rows.length;index++) {
    const row=rows[index]!,offset=start+index*16,end=Math.min(offset+16,start+256,bytes.length)
    const first=Math.max(offset,range.offset),last=Math.min(end,range.offset+range.length),newline=index===rows.length-1?'':'\n'
    if(first>=last) {result.push({text:row+newline,matched:false});continue}
    const left=10+(first-offset)*3,right=10+(last-offset)*3-1
    result.push({text:row.slice(0,left),matched:false},{text:row.slice(left,right),matched:true},{text:row.slice(right)+newline,matched:false})
  }
  return result
}
