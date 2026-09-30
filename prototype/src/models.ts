export type PreviewState = 'data' | 'empty' | 'detail' | 'action' | 'loading' | 'error'
export type PageKind = 'table' | 'overview' | 'screen' | 'search' | 'chat' | 'rule-studio' | 'playbook' | 'retention' | 'topology'
export type CellKind = 'text' | 'status' | 'level' | 'percent' | 'code' | 'progress'
export interface ColumnSpec { key: string; title: string; width?: number; kind?: CellKind }
export interface FieldSpec {
  key: string; label: string; type?: 'text' | 'select' | 'number' | 'textarea' | 'switch' | 'password'
  required?: boolean; options?: string[]; value?: string | number | boolean; hint?: string; min?: number; max?: number
}
export interface PageSpec {
  id: string; title: string; group: string; description: string; requirement: string[]; kind: PageKind
  columns: ColumnSpec[]; fields: FieldSpec[]; primary: string; rowAction: string
  emptyTitle: string; emptyDescription: string; notice?: string; detailTabs?: string[]
  statusOptions?: string[]; objectLabel: string; readOnly?: boolean; actionHint?: string
  family: string; actionMode?: 'create' | 'edit' | 'task' | 'export'; extra?: string
}
export interface GroupSpec { id: string; title: string; icon: string }
export type RecordValue = string | number | boolean | null
export interface BusinessRecord { id: string; name: string; status: string; [key: string]: RecordValue }
export interface MetricSpec { label: string; value: string; suffix?: string; note?: string; tone?: 'danger' | 'warning' | 'success' }
