import {compareQuantity,formatBitRate,formatQuantity} from '../../../web/packages/shared/src/utils/format'
import type {ColumnSpec} from '../models'

const percent=new Intl.NumberFormat('zh-CN',{style:'percent',maximumFractionDigits:2})
const quantityKeys=['bytes','bps','rx','speed','estimate','used','limit','stream','http','file']
export function compareCells(left:unknown,right:unknown,column:ColumnSpec):number{
  return quantityKeys.includes(column.key)?compareQuantity(left,right):String(left??'').localeCompare(String(right??''),'zh-CN',{numeric:true})
}
export function formatCell(value:unknown,column:ColumnSpec):string{
  if(value===null||value===undefined)return '未提供'
  if(column.kind==='percent'&&Number.isFinite(Number(value))){
    // 置信度统一保存为 0–1；CPU、覆盖率等遥测百分数保存为 0–100。
    return percent.format(column.key==='confidence'?Number(value):Number(value)/100)
  }
  if(['bps','speed'].includes(column.key)&&(typeof value==='number'||typeof value==='bigint'||/^\d+$/.test(String(value))))return formatBitRate(value as number|string|bigint)
  if(quantityKeys.includes(column.key))return formatQuantity(value)
  return String(value)
}
