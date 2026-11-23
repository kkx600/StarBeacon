// 界面状态用语标准：同一个意思只用一个词。页面不自造说法，新增状态先在这里登记。
// 完整的对照表见仓库根目录 DESIGN.md 的“用语”一节。
export type StatusTone = 'critical' | 'danger' | 'warning' | 'success' | 'info' | 'neutral';

export const statusTerms = {
  // 严重级别
  严重: 'critical',
  高危: 'danger',
  中危: 'warning',
  低危: 'neutral',
  // 连接
  在线: 'success',
  离线: 'neutral',
  // 健康
  正常: 'success',
  需关注: 'warning',
  异常: 'danger',
  // 启停
  草稿: 'neutral',
  启用: 'success',
  停用: 'neutral',
  // 机器执行的任务
  排队中: 'neutral',
  运行中: 'info',
  重试中: 'info',
  已完成: 'success',
  失败: 'danger',
  已取消: 'neutral',
  // 需要人处理的事项
  待处理: 'warning',
  处理中: 'info',
  待复核: 'warning',
  已关闭: 'neutral',
  // 告警
  待研判: 'warning',
  研判中: 'info',
  已关联事件: 'neutral',
  误报: 'neutral',
  // 验证
  待验证: 'warning',
  已验证: 'success',
  验证失败: 'danger',
  // 确认
  待确认: 'warning',
  已确认: 'success',
  已驳回: 'neutral',
  // 设备动作的结果
  已生效: 'success',
  未执行: 'neutral',
  结果未知: 'warning',
  已撤销: 'neutral',
  已过期: 'neutral',
  // 数据
  无数据: 'neutral',
  未采集: 'neutral',
  不完整: 'warning',
  无权限: 'neutral',
  // 研判结论
  真实攻击: 'danger',
  可疑: 'warning',
  证据不足: 'warning',
  // 功能
  未提供: 'neutral',
  未启用: 'neutral',
  未配置: 'warning',
  不支持: 'neutral',
} as const satisfies Record<string, StatusTone>;

export type StatusTerm = keyof typeof statusTerms;

// 返回标准用语对应的色调；不是标准用语时返回 undefined。
// 只认自有键，避免 constructor、toString 这类原型属性被当成标准用语。
export function toneOf(value: string): StatusTone | undefined {
  return Object.hasOwn(statusTerms, value) ? (statusTerms as Record<string, StatusTone>)[value] : undefined;
}
