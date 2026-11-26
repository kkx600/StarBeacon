import type { SearchRequest } from '@starbeacon/shared/types.ts';

const severityWords = { 严重: 'critical', 高危: 'high', 中危: 'medium', 低危: 'low' } as const;

export function naturalAlertQuery(input: string, end = new Date()): SearchRequest {
  const text = input.trim();
  if (!text || new TextEncoder().encode(text).length > 256) throw new Error('请输入不超过 256 字节的检索描述。');
  const quoted = text.match(/[“"]([^”"]+)[”"]/u);
  const filters = text.replace(/[“"][^”"]+[”"]/gu, '');
  const period = filters.match(/(?:最近|过去|近)\s*(\d{1,3})\s*(小时|天)/u);
  const hours = period ? Number(period[1]) * (period[2] === '天' ? 24 : 1) : 24;
  if (hours < 1 || hours > 31 * 24) throw new Error('检索时间须在 1 小时至 31 天之间。');
  const severities = Object.entries(severityWords).filter(([name]) => filters.includes(name));
  if (severities.length > 1) throw new Error('每次检索请选择一个告警级别。');
  const keyword =
    quoted?.[1]?.trim() ??
    filters
      .replace(/(?:请|帮我|检索|搜索|查找|查询|查看|告警|包含|关键字|关键词|规则名称|[：:，。？！、？!])/gu, '')
      .replace(/(?:最近|过去|近)\s*\d{1,3}\s*(小时|天)/gu, '')
      .replace(/严重|高危|中危|低危/gu, '')
      .replace(/^\s*的\s*|\s*的\s*$/gu, '')
      .trim();
  return {
    start: new Date(end.getTime() - hours * 3600000).toISOString(),
    end: end.toISOString(),
    page: 1,
    page_size: 10,
    keyword,
    source_ip: '',
    destination_ip: '',
    protocol: '',
    method: '',
    path: '',
    severity: severities[0]?.[1] ?? '',
  };
}
