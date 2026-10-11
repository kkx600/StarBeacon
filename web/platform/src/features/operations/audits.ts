export const actionNames:Record<string,string>={
  'users.create':'创建用户','users.change':'变更用户权限','users.password.change':'修改自身密码',
  'users.password.reset':'重置成员密码','users.password.denied':'密码操作验证失败','users.password.recover':'离线恢复管理员密码',
  'sensor.active=true':'启用探针','sensor.active=false':'停用探针',
  'rule.package.save':'保存规则包修订','replay.sample.import':'导入重放样本',
  'sensor.task.diagnostics':'提交运行诊断','sensor.task.rules.validate':'提交规则装载检查',
  'sensor.task.rules.replay':'提交 PCAP 重放','sensor.task.rules.apply':'提交规则同步',
  'sensor.task.cancel':'取消探针任务','inventory.assets.save':'保存资产修订',
  'inventory.groups.save':'保存资产组修订','inventory.networks.save':'保存网段修订',
  'notifications.channel.save':'保存通知渠道修订','notifications.channel.test':'提交通知渠道测试',
  'notifications.delivery.retry':'提交通知人工重试',
  'models.provider.save':'保存模型提供方修订','models.provider.test':'提交模型连接验证',
  'analysis.create':'提交智能分析或统计报告','analysis.cancel':'申请取消智能分析',
  'reports.plan.save':'保存报告计划','reports.plan.suspend':'停止无资格报告计划',
  'alerts.assessment.save':'保存告警研判',
  'auth.password_verification':'验证登录凭据',
}
export const actionLabel=(action:string)=>actionNames[action]??'其他操作'
