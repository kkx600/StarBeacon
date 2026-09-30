import { computed, reactive } from 'vue'
import type { BusinessRecord, PageSpec } from '../models'
import { createFixtures } from '../data/fixtures'
import {initialStatusFor} from '../data/statuses'
import {formatCell} from './formatRecord'

const recordsByPage = reactive<Record<string,BusinessRecord[]>>({})
export function useRecords(page: PageSpec) {
  if (!recordsByPage[page.id]) recordsByPage[page.id] = createFixtures(page)
  const records = computed(() => recordsByPage[page.id]!)
  function save(values: Record<string,unknown>, recordId?: string) {
    const items = recordsByPage[page.id]!
    const index = items.findIndex(r => r.id === recordId)
    const clean = Object.fromEntries(Object.entries(values).filter(([key,value]) => key!=='id'&&['string','number','boolean'].includes(typeof value))) as Partial<BusinessRecord>
    if (index>=0) items[index] = {...items[index]!,...clean,updated:'2026-09-30 09:48:00'}
    else items.unshift({...clean,id:`${page.id.toUpperCase()}-LOCAL-${Date.now()}`,name: typeof values.name==='string' && values.name ? values.name : `${page.objectLabel}示例记录`,status:typeof clean.status==='string'?clean.status:initialStatusFor(page),updated:'2026-09-30 09:48:00'})
  }
  function updateStatus(ids: string[], status: string) { for(const record of recordsByPage[page.id]!) if(ids.includes(record.id)){record.status=status;if(page.family==='action'&&status==='撤销待核验'){record.effective='撤销待核验';record.observed='无法判定'}} }
  return {records,save,updateStatus}
}

function download(content: string, name: string, type: string) {
  const url=URL.createObjectURL(new Blob([content],{type}))
  const a=document.createElement('a');a.href=url;a.download=name;a.click()
  setTimeout(() => URL.revokeObjectURL(url),1000)
}
export function exportCsv(page: PageSpec, records: BusinessRecord[]) {
  // 将可能被表格软件解释成公式的首字符作为文本，防止导出内容执行公式。
  const escape=(value: unknown) => {
    const raw=String(value??'');const safe=/^[=+@\-\t\r]/.test(raw)?`'${raw}`:raw
    return `"${safe.replace(/"/g,'""')}"`
  }
  const text=[page.columns.map(c=>escape(c.title)).join(','),...records.map(r=>page.columns.map(c=>escape(formatCell(r[c.key],c))).join(','))].join('\r\n')
  download(`\ufeff${text}`,`${page.id}-example.csv`,'text/csv;charset=utf-8')
}
export function exportJson(name: string, value: unknown) { download(JSON.stringify(value,null,2),`${name}-example.json`,'application/json') }
