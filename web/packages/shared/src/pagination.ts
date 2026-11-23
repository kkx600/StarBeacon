// 全部列表共用的分页标准：每页条数、默认值和总数文案只在这里定义。
export const pageSizeOptions = [10, 20, 50, 100] as const;
export const defaultPageSize = 20;

export function totalText(total: number | bigint | string): string {
  return `共 ${BigInt(total).toLocaleString('zh-CN')} 条`;
}

// 取出当前页的记录；页码超出范围时回到最后一页。
export function pageOf<T>(rows: readonly T[], page: number, pageSize: number): T[] {
  const last = Math.max(1, Math.ceil(rows.length / pageSize));
  const current = Math.min(Math.max(1, page), last);
  return rows.slice((current - 1) * pageSize, current * pageSize);
}

// 组件库表格自带分页时使用的标准配置（本地数据的页码分页）。
export function tablePagination() {
  return {
    defaultPageSize,
    pageSizeOptions: pageSizeOptions.map(String),
    showSizeChanger: true,
    showTotal: totalText,
    size: 'small' as const,
  };
}
