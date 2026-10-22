import type {LocationQuery,LocationQueryRaw} from 'vue-router'

export const packetPreviewModes=['data','loading','error','empty','expired','corrupt'] as const
export type PacketPreviewMode=typeof packetPreviewModes[number]
export interface PacketPreviewLocation {
 open:boolean
 archive?:string
 number:number
 layer:number|null
 mode:PacketPreviewMode
 error:string
}
const keys=['inspect','inspect_archive','packet','layer','inspection'] as const
const positive=(value:unknown,maximum:number)=>typeof value==='string'&&/^[1-9][0-9]*$/.test(value)&&Number.isSafeInteger(Number(value))&&Number(value)<=maximum?Number(value):null

// 专项查看参数只接受规范标量，避免重复参数或隐式数值转换改变所见样本。
export function packetPreviewLocation(query:Readonly<LocationQuery>,layers:readonly number[]):PacketPreviewLocation {
 const result:PacketPreviewLocation={open:query.inspect!==undefined,number:1,layer:1,mode:'data',error:''}
 if(!result.open)return result
 const fail=(message:string)=>{result.mode='error';result.error=message;return result}
 if(query.inspect!=='packet')return fail('原包查看方式无效，请重新从归档列表进入')
 if(query.inspect_archive!==undefined){
  if(typeof query.inspect_archive!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(query.inspect_archive))return fail('原包目录标识无效，请重新选择合成目录')
  result.archive=query.inspect_archive
 }
 const number=positive(query.packet===undefined?'1':query.packet,layers.length)
 if(number===null)return fail(`包序号应为 1–${layers.length} 的规范整数`)
 result.number=number
 if(query.layer==='none')result.layer=null
 else {
  const layer=positive(query.layer===undefined?'1':query.layer,layers[number-1]??0)
  if(layer===null)return fail('协议层不在当前样本报文的有效范围内')
  result.layer=layer
 }
 const mode=query.inspection===undefined?'data':query.inspection
 if(typeof mode!=='string'||!packetPreviewModes.includes(mode as PacketPreviewMode))return fail('原包查看状态无效，请重新选择状态示例')
 result.mode=mode as PacketPreviewMode
 return result
}

export function closePacketPreview(query:Readonly<LocationQuery>):LocationQueryRaw {
 const result:LocationQueryRaw={...query}
 for(const key of keys)delete result[key]
 return result
}

export function openPacketPreview(query:Readonly<LocationQuery>,archive?:string):LocationQueryRaw {
 return {...closePacketPreview(query),inspect:'packet',...(archive?{inspect_archive:archive}:{}),packet:'1',layer:'1',inspection:'data'}
}

export function selectPacketPreview(query:Readonly<LocationQuery>,number:number):LocationQueryRaw {
 if(!Number.isSafeInteger(number)||number<1||number>1048576)throw new RangeError('包序号无效')
 return {...query,packet:String(number),layer:'1'}
}

export function selectPacketLayer(query:Readonly<LocationQuery>,layers:readonly number[]):LocationQueryRaw {
 if(layers.some(layer=>!Number.isSafeInteger(layer)||layer<1||layer>16))throw new RangeError('协议层序号无效')
 return {...query,layer:layers.length?String(layers[0]):'none'}
}
