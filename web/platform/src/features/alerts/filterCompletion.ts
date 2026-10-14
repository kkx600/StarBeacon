export interface SearchField { name: string; label: string; type: string; aliases: string[]; operators: string[] }
export interface CompletionRange { start: number; end: number; prefix: string }
const tokenCharacter = /[A-Za-z0-9_@.]/
const types = new Set(['protocol', 'ip', 'mac', 'port', 'identifier', 'time', 'string', 'keyword', 'text'])
const operators = new Set(['exists', '==', '!=', 'in', '>', '>=', '<', '<=', 'contains'])

export function readSearchFields(value: unknown): SearchField[] {
  if (!value || typeof value !== 'object' || !('fields' in value) || !Array.isArray(value.fields) || value.fields.length > 256) throw new Error('检索字段目录不完整，请重试')
  const names = new Set<string>()
  return value.fields.map((field: unknown) => {
    if (!field || typeof field !== 'object') throw new Error('检索字段目录格式无效')
    const f = field as Record<string, unknown>
    if (typeof f.name !== 'string' || !/^[@A-Za-z_][A-Za-z0-9_@.]{0,127}$/.test(f.name) || names.has(f.name)
      || typeof f.label !== 'string' || !f.label || f.label.length > 256 || typeof f.type !== 'string' || !types.has(f.type)
      || !Array.isArray(f.aliases) || f.aliases.length > 32 || f.aliases.some(a => typeof a !== 'string' || !/^[@A-Za-z_][A-Za-z0-9_@.]{0,127}$/.test(a))
      || !Array.isArray(f.operators) || f.operators.length > 16 || f.operators.some(o => typeof o !== 'string' || !operators.has(o))) throw new Error('检索字段目录格式无效')
    names.add(f.name)
    return { name: f.name, label: f.label, type: f.type, aliases: [...f.aliases] as string[], operators: [...f.operators] as string[] }
  })
}

export function completionRange(source: string, cursor: number): CompletionRange | undefined {
  if (!Number.isInteger(cursor) || cursor < 0 || cursor > source.length) return
  let quoted = false, escaped = false
  for (let i = 0; i < cursor; i++) {
    const c = source[i]
    if (escaped) { escaped = false; continue }
    if (quoted && c === '\\') { escaped = true; continue }
    if (c === '"') quoted = !quoted
  }
  if (quoted) return
  let start = cursor, end = cursor
  while (start > 0 && tokenCharacter.test(source[start - 1]!)) start--
  while (end < source.length && tokenCharacter.test(source[end]!)) end++
  return { start, end, prefix: source.slice(start, cursor) }
}

export function suggestFields(source: string, cursor: number, fields: readonly SearchField[], explicit = false): SearchField[] {
  const range = completionRange(source, cursor)
  if (!range || (!range.prefix && !explicit)) return []
  const prefix = range.prefix.toLowerCase()
  return fields.filter(field => [field.name, ...field.aliases].some(name => name.toLowerCase().startsWith(prefix))).slice(0, 8)
}

export function insertSearchField(source: string, cursor: number, field: SearchField): { value: string; cursor: number } {
  const range = completionRange(source, cursor)
  const replace = range && (range.prefix ? [field.name, ...field.aliases].some(name => name.toLowerCase().startsWith(range.prefix.toLowerCase())) : !source.slice(0, cursor).trim() || /(?:\b(?:and|or|not)|&&|\|\||[(!])\s*$/.test(source.slice(0, cursor)))
  const start = replace ? range.start : source.length
  const end = replace ? range.end : source.length
  const before = source.slice(0, start), after = source.slice(end)
  const join = replace || !source.trim() ? '' : `${/\s$/.test(before) ? '' : ' '}and `
  const existingComparison = /^\s*(?:==|!=|>=|<=|>|<|\b(?:eq|ne|ge|le|gt|lt|contains|in)\b)/.test(after)
  const operator = field.operators.includes('==') ? '==' : field.operators.find(o => o !== 'exists') ?? '=='
  const suffix = field.type === 'protocol' || existingComparison ? '' : ` ${operator} `
  const inserted = `${join}${field.name}${suffix}`
  return { value: before + inserted + after, cursor: before.length + inserted.length }
}
