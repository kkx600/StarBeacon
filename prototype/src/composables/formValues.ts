import type {BusinessRecord,FieldSpec} from '../models'

export const examplePermissionCounts:Record<string,number>={'安全分析员':28,'响应审批员':12,'租户管理员':56,'只读审计员':8}

export function expiryFromDuration(value:string,reference:string):string|undefined {
  const duration=value.match(/^(\d+)\s*(天|小时)$/)
  if(!duration)return undefined
  return new Date(Date.parse(reference)+Number(duration[1])*(duration[2]==='天'?86400000:3600000)).toISOString().slice(0,19).replace('T',' ')
}

// 展示值可带单位；编辑控件只接收所属字段的值域，保留身份与统计字段的独立含义。
export function formValueFor(field:FieldSpec,record?:BusinessRecord):unknown {
  const value=record?.[field.key]??field.value??(field.type==='switch'?false:'')
  if(field.type==='number'){
    if(typeof value==='number')return value
    const match=String(value).match(/^(\d+(?:\.\d+)?)\s*(?:MiB|秒|分钟|天|次／分钟)?$/)
    return match?Number(match[1]):field.value
  }
  if(field.type==='switch')return typeof value==='boolean'?value:typeof field.value==='boolean'?field.value:false
  if(field.type==='select'&&field.options&&!field.options.includes(String(value)))return undefined
  return value
}
