export interface RuleDiagnostic {from: number; to: number; line: number; severity: 'error' | 'warning'; message: string}
export const RULE_LIMIT = 900 * 1024

// 这里只检查编辑阶段可确定的结构；关键词、变量、协议与运行配置交由目标 Suricata 验证。
export function inspectRules(text: string): RuleDiagnostic[] {
  const diagnostics: RuleDiagnostic[] = []
  const add = (from: number, to: number, line: number, message: string) => {
    if (diagnostics.length < 50) diagnostics.push({from, to: Math.max(from, to), line, severity: 'error', message})
  }
  if (new TextEncoder().encode(text).length > RULE_LIMIT) { add(0, 0, 1, '规则文本超过 900 KiB，请拆分规则包。'); return diagnostics }
  if (!text.trim()) return [{from: 0, to: 0, line: 1, severity: 'error', message: '请输入至少一条 alert 检测规则。'}]
  let offset = 0, count = 0
  const sids = new Map<string, number>()
  for (const [index, raw] of text.split('\n').entries()) {
    const line = index + 1, start = offset
    offset += raw.length + 1
    const value = raw.trim()
    if (!value || value.startsWith('#')) continue
    count++
    const at = start + raw.indexOf(value)
    if (value.includes('\0')) { add(at, at + value.length, line, '规则不能包含空字符。'); continue }
    const open = value.indexOf('(')
    if (open < 0 || !value.endsWith(')')) { add(at, at + value.length, line, '每行需包含完整规则头与 (...) 选项，不能跨行。'); continue }
    const header = value.slice(0, open).match(/\[[^\]]*\]|[^\s]+/g) ?? []
    if (header.length !== 7 || !['->', '<>'].includes(header[4] ?? '')) add(at, at + open, line, '规则头应为：alert 协议 源地址 源端口 -> 目的地址 目的端口。')
    if (header[0] !== 'alert') add(at, at + (header[0]?.length ?? 1), line, '旁路规则仅接受 alert 动作，其他动作需独立授权。')
    const body = value.slice(open + 1, -1), parts: {text: string; at: number}[] = []
    let quoted = false, escaped = false, part = 0
    for (let n = 0; n < body.length; n++) {
      const character = body[n]
      if (escaped) { escaped = false; continue }
      if (character === '\\') { escaped = true; continue }
      if (character === '"') quoted = !quoted
      if (!quoted && character === ';') { parts.push({text: body.slice(part, n), at: at + open + 1 + part}); part = n + 1 }
    }
    if (quoted || escaped) add(at + open + 1, at + value.length - 1, line, '引号或转义未闭合，请核对字符串内容。')
    if (body.slice(part).trim()) add(at + open + 1 + part, at + value.length - 1, line, '最后一个规则选项需以分号结尾。')
    const sidParts = parts.filter(p => /^\s*sid\s*:/.test(p.text))
    if (sidParts.length !== 1) { add(at, at + value.length, line, '每条规则需包含且仅包含一个 sid。'); continue }
    const sidPart = sidParts[0]!, sid = /^\s*sid\s*:\s*(\d+)\s*$/.exec(sidPart.text)?.[1]
    if (!sid || BigInt(sid) < 1n || BigInt(sid) > 4294967295n) add(sidPart.at, sidPart.at + sidPart.text.length, line, 'SID 应为 1–4294967295 的整数。')
    else if (sids.has(BigInt(sid).toString())) add(sidPart.at, sidPart.at + sidPart.text.length, line, `SID ${sid} 与第 ${sids.get(BigInt(sid).toString())} 行重复。`)
    else sids.set(BigInt(sid).toString(), line)
    for (const p of parts.filter(p => /^\s*rev\s*:/.test(p.text))) if (!/^\s*rev\s*:\s*[1-9]\d*\s*$/.test(p.text)) add(p.at, p.at + p.text.length, line, '修订 rev 应为正整数。')
  }
  if (!count) add(0, 0, 1, '规则包没有检测规则，仅注释无法执行验证。')
  return diagnostics
}
