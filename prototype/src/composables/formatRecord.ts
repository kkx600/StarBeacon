import type {ColumnSpec} from '../models'

const percent=new Intl.NumberFormat('zh-CN',{style:'percent',maximumFractionDigits:2})
export function formatCell(value:unknown,column:ColumnSpec):string{
  if(value===null||value===undefined)return '未提供'
  if(column.kind==='percent'&&Number.isFinite(Number(value))){
    // 置信度统一保存为 0–1；CPU、覆盖率等遥测百分数保存为 0–100。
    return percent.format(column.key==='confidence'?Number(value):Number(value)/100)
  }
  return String(value)
}
