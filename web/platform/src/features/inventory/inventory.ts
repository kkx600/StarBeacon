export type InventoryKind='assets'|'groups'|'networks'
export interface AssetInterface {name:string;mac:string;ips:string[]}
export interface InventoryData {name:string;active:boolean;description:string;owner?:string;group_id?:string;network_domain?:string;criticality?:string;interfaces?:AssetInterface[];prefix?:string;purpose?:string}
export interface InventoryRecord {id:string;kind:InventoryKind;revision:number;data:InventoryData;created_at:string;updated_at:string}
export interface InventoryPage {items:InventoryRecord[];next_cursor:string}
export const inventoryNames:Record<InventoryKind,string>={assets:'资产目录',groups:'资产组',networks:'网段定义'}
export const inventoryObjectNames:Record<InventoryKind,string>={assets:'资产',groups:'资产组',networks:'网段'}
export const criticalityNames:Record<string,string>={critical:'关键',high:'重要',normal:'一般',low:'低'}
export const purposeNames:Record<string,string>={internal:'内部网络',external:'外部网络',excluded:'禁止响应范围'}
export function createDraft(kind:InventoryKind,data?:InventoryData):InventoryData {
  if(data)return JSON.parse(JSON.stringify(data)) as InventoryData
  const base={name:'',active:true,description:''}
  if(kind==='groups')return {...base,owner:''}
  if(kind==='networks')return {...base,group_id:'',network_domain:'default',prefix:'',purpose:'internal'}
  return {...base,owner:'',group_id:'',network_domain:'default',criticality:'normal',interfaces:[]}
}
export function details(record:InventoryRecord):{label:string;value:string}[] {
  const data=record.data,rows=[{label:'名称',value:data.name},{label:'状态',value:data.active?'使用中':'已停用'},{label:'修订',value:String(record.revision)}]
  if(record.kind==='assets'||record.kind==='groups')rows.push({label:'责任人',value:data.owner||'未指定'})
  if(record.kind!=='groups')rows.push({label:'网络域',value:data.network_domain||'未指定'},{label:'资产组标识',value:data.group_id||'未分组'})
  if(record.kind==='assets')rows.push({label:'重要性',value:criticalityNames[data.criticality??'']??'未指定'},{label:'网络接口',value:data.interfaces?.map(iface=>`${iface.name} · ${iface.mac||'未配置 MAC'} · ${iface.ips.join('、')||'未配置 IP'}`).join('\n')||'未配置网络接口'})
  if(record.kind==='networks')rows.push({label:'网段',value:data.prefix||'未配置'},{label:'用途',value:purposeNames[data.purpose??'']??'未指定'})
  rows.push({label:'说明',value:data.description||'无'})
  return rows
}
