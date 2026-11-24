---
name: "星烽 StarBeacon"
description: "以记录、证据与受控操作为中心的安全运营控制台设计系统。"
colors:
  primary: "#2f54eb"
  primary-hover: "#597ef7"
  primary-active: "#1d39c4"
  action: "#2f54eb"
  action-hover: "#597ef7"
  action-active: "#1d39c4"
  link: "#2f54eb"
  surface: "#ffffff"
  workspace: "#f4f4f4"
  line: "#e5e5e5"
  control-border: "#d9d9d9"
  control-hover: "#597ef7"
  control-disabled: "#f5f5f5"
  text-disabled: "#bfbfbf"
  scrollbar: "#e0e3e9"
  text: "#29343d"
  muted: "#6b6b6b"
  text-placeholder: "#8c8c8c"
  field-label: "#6b6b6b"
  record-text: "#29343d"
  table-header: "#fafafa"
  row-hover: "#fafafa"
  nav-selected: "#f0f0f0"
  tab-selected: "#f3f3f3"
  selection-surface: "#f0f5ff"
  selection-text: "#1d39c4"
  success: "#2a7e3b"
  success-dot: "#3a9e50"
  warning: "#9a5b00"
  warning-dot: "#e08a00"
  danger: "#c4262e"
  danger-dot: "#e5484d"
  critical: "#b42318"
  critical-text: "#ffffff"
  progress-surface: "#eef2ff"
  progress-text: "#2f54eb"
  status-surface: "#f2f2f2"
  status-text: "#595959"
  success-surface: "#ecf8ee"
  warning-surface: "#fff4dc"
  danger-surface: "#fdeceb"
  info-surface: "#fafafa"
  info-text: "#29343d"
  info-dot: "#2f54eb"
  warning-border: "#f5d48a"
  teal: "#0095ad"
  violet: "#8950e9"
  chart-orange: "#d97900"
  chart-neutral: "#8c8c8c"
  chart-grid: "#ededed"
  screen-workspace: "#181818"
  screen-panel: "#222222"
  screen-metric: "#262626"
  screen-line: "#404040"
  screen-text: "#ecf6ff"
  screen-muted: "#bddefa"
  screen-number: "#8ce6ff"
  screen-link: "#70d0ff"
  screen-blue: "#4cbcff"
  screen-teal: "#3ee0ba"
  screen-amber: "#ffd174"
  screen-danger: "#ffa0b2"
  screen-chart-blue: "#56a9df"
  screen-chart-teal: "#36ad94"
  screen-chart-violet: "#906acb"
  screen-chart-amber: "#d9a652"
  syntax-variable: "#7434bb"
  syntax-option: "#8a4700"
  syntax-number: "#b42340"
  syntax-keyword: "#1d39c4"
  syntax-string: "#087a43"
typography:
  page-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: 1.35
    letterSpacing: "-0.2px"
  detail-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "20px"
  section-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.5
  panel-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.5
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "14px"
  button:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: "22px"
  record-link:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "13px"
    fontWeight: 500
  field-label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "12px"
  caption:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "12px"
  status-label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "12px"
    lineHeight: 1.5
  technical:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "12px"
  rule-editor:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "13px"
    lineHeight: 1.65
  metric:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "20px"
    fontWeight: 600
    lineHeight: "28px"
  metric-dark:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: 1.25
rounded:
  control: "8px"
  panel: "8px"
  tag: "4px"
  nested: "6px"
  modal: "12px"
  selected-byte: "2px"
spacing:
  page-inset: "16px"
  section-gap: "12px"
  panel-inset: "16px"
  field-gap: "12px"
  related-gap: "8px"
  label-gap: "4px"
components:
  button-primary:
    backgroundColor: "{colors.action}"
    textColor: "{colors.surface}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "5px 15px"
    height: "34px"
  button-primary-hover:
    backgroundColor: "{colors.action-hover}"
  button-primary-active:
    backgroundColor: "{colors.action-active}"
  record-link:
    backgroundColor: "transparent"
    textColor: "{colors.link}"
    typography: "{typography.record-link}"
    padding: "0px"
  query-example:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    rounded: "{rounded.tag}"
    padding: "4px 8px"
  query-editor:
    backgroundColor: "{colors.table-header}"
    rounded: "{rounded.nested}"
  rule-editor:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.rule-editor}"
    rounded: "{rounded.control}"
    padding: "0px"
  workspace-tab:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "6px 6px 0px 0px"
    padding: "0px 15px"
    height: "36px"
  workspace-tab-active:
    backgroundColor: "{colors.tab-selected}"
    textColor: "{colors.link}"
  status-tag:
    backgroundColor: "{colors.status-surface}"
    textColor: "{colors.status-text}"
    typography: "{typography.status-label}"
    rounded: "{rounded.tag}"
    padding: "1px 7px"
  status-tag-warning:
    backgroundColor: "{colors.warning-surface}"
    textColor: "{colors.warning}"
  status-tag-success:
    backgroundColor: "{colors.success-surface}"
    textColor: "{colors.success}"
  status-tag-danger:
    backgroundColor: "{colors.danger-surface}"
    textColor: "{colors.danger}"
  status-tag-info:
    backgroundColor: "{colors.progress-surface}"
    textColor: "{colors.progress-text}"
  status-tag-critical:
    backgroundColor: "{colors.critical}"
    textColor: "{colors.critical-text}"
  metric:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.metric}"
  metric-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.danger}"
  metric-warning:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.warning}"
  metric-dark:
    backgroundColor: "{colors.screen-metric}"
    textColor: "{colors.screen-number}"
    typography: "{typography.metric-dark}"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
  table-header:
    backgroundColor: "{colors.table-header}"
    textColor: "{colors.field-label}"
    typography: "{typography.field-label}"
    padding: "12px 14px"
  evidence-strip:
    rounded: "{rounded.control}"
    padding: "{spacing.section-gap}"
  packet-byte-selected:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.selected-byte}"
    padding: "1px 1px"
  execution-receipt:
    backgroundColor: "{colors.table-header}"
    textColor: "{colors.text}"
    typography: "{typography.technical}"
    rounded: "{rounded.control}"
    padding: "{spacing.section-gap}"
  screen-panel:
    backgroundColor: "{colors.screen-panel}"
    textColor: "{colors.screen-text}"
    rounded: "{rounded.control}"
---
# Design System: 星烽 StarBeacon

## Overview

**Creative North Star: "清晰的安全运营工作台"**

星烽 StarBeacon 采用用户指定的后台布局，以白色导航、白色指标与内容面板、纯浅灰工作区和明亮蓝色动作形成清晰的安全运营环境。表格、表单、详情与操作弹窗承载主要工作；视觉层级服务于识别对象、核对依据和执行获准动作。

工作区保持足够的信息密度，以文字、对齐、细边框与留白区分内容。记录名称可进入详情，严重级别与执行状态同时提供可读文字和颜色。态势大屏使用独立深灰工作区、高亮蓝青数字和玫红风险值；这套局部配色不改变控制台的浅色基准。

本系统的基础规范来自 Vue 3、TypeScript 与 Ant Design Vue 原型；原型全部使用合成数据，操作仅改变本地内存。`web/` 工程沿用同一调色板和空间变量，以实际 API 状态承载业务。PCAP 重放的任务与结果来自真实执行；原型交互覆盖、工程实现范围与部署验收各自保留证据边界，设计说明不承担生产能力或性能验收。

**Key Characteristics:**

- 白色导航、指标与结构面板，纯浅灰工作区与认证背景；靛蓝主色同时表达动作、链接与选择状态。
- 仅面向 PC 桌面，最小支持宽度为 1024px；表格、表单、详情和操作弹窗使用一致的空间与状态语言。
- 系统中文字体、等宽技术字段和等宽数字分别承担阅读、取证与数值比较。
- 证据不足、无数据、运行模式与生命周期各自保持独立含义。

颜色取值依据为 [主题文件](prototype/src/theme.ts)，共享样式依据为 [实际样式](prototype/src/styles.css)。[应用入口](prototype/src/main.ts)在挂载前把调色板写入根级 CSS 变量，覆盖主平台、采集器和挂载到 body 的弹窗、通知；[应用主题](prototype/src/App.vue)将同一配置交给 Ant Design Vue。组件配置按固定版本 4.2.6 的实际接口使用 Menu.colorItemText、colorItemBgSelected 等取值；基础色为靛蓝主色、成功绿、警示橙和错误红，信息色与主色相同；按钮、链接、开关、选择标记和交互状态由 defaultAlgorithm 生成，四类提示的底色与边框在主题文件里显式给出，不把较深的业务文字色作为组件基础色。链接全局 Token 使用主色，与记录入口一致。导航选中项仍使用纯灰表面；表格与下拉选中项使用组件默认派生浅底，页面工作区和面板保持原白灰背景。原型不覆盖 Alert 底色或图标色。

工程的 [共享主题](web/packages/shared/src/theme.ts)保留同一角色配色，`applyPalette` 将其写入根级 CSS 变量；[共享样式](web/packages/shared/src/styles.css)沿用六项空间变量。[规则编辑器](web/packages/shared/src/components/RuleEditor.vue)由两端工程与原型直接复用，基础诊断依据为[受控规则检查](web/packages/shared/src/utils/ruleSyntax.ts)，数值表示依据为[容量与速率工具](web/packages/shared/src/utils/format.ts)。PCAP 重放依据 [功能与部署边界](docs/PCAP重放与规则验证.md)、[样本工作区](web/packages/shared/src/components/ReplayWorkspace.vue)、[检测结果](web/packages/shared/src/components/ReplayResult.vue)和[任务详情](web/packages/shared/src/components/TaskTable.vue)记录。既有原型导航数量、局部布局与评审数据只适用于原型；工程组件的局部差异不重定义共用 token。

设计依据为用户指定布局、产品约束、实际代码和截图。配色回归脚本核对组件基础色、实际派生表面、三个入口的颜色变量、局部覆盖和上下文消息；67 组正文、操作、导航、业务标签和规则语法组合对比度至少 4.5:1，9 组图表组合至少 3:1。控件边界及占位提示另行记录实际对比度，不声明全界面 AA。静态检查不替代所有交互状态的可访问性验收。2026-10-17 的 833 张原型图均来自内置浏览器按当前共享主题实际渲染，保留来源、视口、主题摘要和 SHA-256。159 项响应式 DOM 观察覆盖全部 124 个工作区的 1024×600 操作状态，以及七个代表表单的五档尺寸。代表页面另做人工视觉和操作检查；数量与来源不推定逐图人工视觉、性能或生产验收。侧车色带属于设计面板预览，不是界面 token。操作消息通过组件库 App 与 useMessage 上下文继承主题，不依赖根级 CSS 变量改变静态 API 的内部主题。

## 改版（2026-11-20）

本章记录 2026-11-20 确定的界面调整和落地范围。已落地的取值同时写进了 frontmatter；尚未落地的部分在[开发任务](docs/开发任务.md)里排期，落地后从下表改为“已落地”。

### 落地范围

| 内容 | 原型 | 主控平台与采集器 |
| --- | --- | --- |
| 配色（共享主题） | 已落地 | 已落地，同一份主题文件 |
| 紧凑布局、页面头部 | 已落地 | 已落地（T16–T19 的工作区） |
| 指标条 | 已采用共享组件 | 运行状态、原包存储、历史影响预览已采用共享组件 |
| 列表：编号独立成列、一行一条、统一分页 | 已落地（通用列表页与嵌入页） | 已落地（T16–T19 的工作区） |
| 页面说明收进“?” | 已落地 | 已落地（T16–T19 的工作区） |
| 状态标签六种色调、严重度四级 | 已采用共享组件 | 已落地（T16–T19 的工作区） |
| 系统级配置集中到系统设置 | 已落地 | 未落地 |
| 状态用语统一 | 已落地（原型自有页面） | 未落地 |
| 字号、字重、圆角档位收敛 | 已落地 | 已落地 |
| 当前版本未提供的工作区从侧栏隐藏 | 不涉及 | 未落地 |

原型里直接嵌入工程组件的页面（名单、关联规则、通知、Syslog、探针证书、被动发现、质量事件等）跟随工程端，工程端迁移后才会一致。

### 配色

主色是较深的靛蓝，文字类用色全部达到 4.5:1。白色导航与面板、纯灰工作区和布局骨架不变。

| 角色 | 取值 | 说明 |
| --- | --- | --- |
| 主色（按钮、链接、导航与页签选中、焦点、图表系列一） | `#2f54eb` | 白字 5.85:1；悬停 `#597ef7`，按下 `#1d39c4`，浅底 `#f0f5ff` |
| 信息提示 | 底 `#fafafa`、边 `#e5e5e5`、图标取主色 | 纯灰表面 |
| 成功：文字／浅底／圆点 | `#2a7e3b`／`#ecf8ee`／`#3a9e50` | 4.64:1 |
| 警示：文字／浅底／圆点 | `#9a5b00`／`#fff4dc`／`#e08a00` | 4.97:1；边框 `#f5d48a` |
| 危险：文字／浅底／圆点 | `#c4262e`／`#fdeceb`／`#e5484d` | 5.02:1，用于“高危” |
| 严重 | 白字，实底 `#b42318` | 6.57:1 |
| 中性标签：文字／底 | `#595959`／`#f2f2f2` | 6.26:1，含“低危” |
| 进行中标签 | 文字取主色，底 `#eef2ff` | 5.23:1 |
| 占位提示 | `#8c8c8c` | 3.36:1，不承载必读信息 |
| 控件边界 | `#d9d9d9` | |
| 工作区／分隔线 | `#f4f4f4`／`#e5e5e5` | 纯灰 |

- 指标数字默认用正文色。大于零的风险数字使用警示色或危险色。缺测显示“—”与原因，零值使用默认数值色。
- 严重度四级依次使用实底、危险色、警示色和中性色。告警处理状态单独映射，待研判使用中性色，研判中使用信息色。
- 调用方根据业务状态键赋予标签色调，并独立传入展示文字。未知状态使用中性色。
- 深色面板上的状态标签使用半透明色底和浅色字。严重标签使用实底与白字。
- 图表系列一取主色，青、紫、橙保留，“其他”用中性灰。
- 主题变量按“浅色一组取值、深色一组取值”的结构组织，本轮只提供浅色；变量名不带明暗含义。

### 列表

- 共享的 `ListTable` 提供紧凑表格，`ListFilters` 统一筛选字段、操作和高级条件的布局。预设时段与手动输入起止时间均使用 `TimeRangeField`。
- **编号独立成列**：编号放第一列，用等宽字体；名称列只放名称，不把编号或规则号叠在名称下面。
- **一行一条**：单元格不换行，放不下的用省略号，完整内容在悬停提示和详情里；行高约 40px。1440×900 下列表首屏完整可见不少于 8 行。
- **统一分页**：所有列表用同一个分页条，放在表格右下，只有一页时也显示。
  - 能数出总数的列表：`共 N 条`、页码、每页条数。
  - 只能前后翻页的列表：`第 N 页 · 本页 M 条`、上一页与下一页、每页条数。
  - 每页默认 20 条，可选 10、20、50、100。
  - 实现在 `web/packages/shared/src/pagination.ts` 和 `web/packages/shared/src/components/ListPager.vue`；表格内置分页用 `tablePagination()`。
  - 固定条目的配置表（例如系统设置）不分页。
- **操作列**固定在右侧，最多三个文字按钮，更多的收进“更多”。
- **时间**按浏览器本地时区显示为 `YYYY-MM-DD HH:mm:ss`，时间列保持单行。回放捕获时间保留三位毫秒，证据详情可保留回执的小数位。标为 UTC 的时间按 UTC 显示。
- **数字**用共享格式函数显示千分位，有效整数字符串经 `BigInt` 处理时保留精度。

### 页面说明

- 页面标题右侧的“?”收纳页面说明、使用提示和数据口径，悬停或点击查看。页面上不常驻显示说明段落和信息提示条。
- 只有此刻需要用户处理的事才用页面内提示条（例如“3 个探针需要关注”），并带上去处。
- 表单字段的说明写在字段下方，不超过一行。

### 配置的位置

- **系统级配置全部放在“系统设置”**：凡是会改变系统行为、对所有人生效的设置都在这里，包括用户管理、AI 自动化级别、旁路阻断的开关与策略、全流量的留存与存储、探针健康阈值。系统设置按分类排列，一个分类一块内容。
- **业务页面只展示本页内容**。需要让人知道当前配置时，只读显示一行（例如“留存策略：智能留存”），旁边给一个“修改”链接跳到系统设置的对应分类；页面上不放配置面板、配置弹窗和配置表单。
- **留在页面上的只有本页自己的显示类设置**：表格列显示、保存查询、大屏的展示设置。
- 操作不是配置：确认执行、暂停自动处置、导出这类动作留在页面头部。
- 按条目管理的对象不算系统设置：联动设备、联动插件、决策策略、检测规则留在各自的业务模块里。

### 用语

同一个意思只用一个词，页面不自造说法。标准词登记在 `web/packages/shared/src/terms.ts`，新增状态先登记再使用。

| 含义 | 标准用语 | 不再使用 |
| --- | --- | --- |
| 连接 | 在线、离线 | 已连接、不可达 |
| 健康 | 正常、需关注、异常 | 降级、关注、需要关注、故障 |
| 是否生效的配置 | 草稿、启用、停用 | 已启用、已停用、已生效（指配置） |
| 机器执行的任务 | 排队中、运行中、重试中、已完成、失败、已取消 | 执行中、进行中、生成中、分析中、成功（指任务） |
| 需要人处理的事项 | 待处理、处理中、待复核、已关闭 | 待接单、调查中、修复中、待复测、待核对、待核实 |
| 告警 | 待研判、研判中、已关联事件、误报、已关闭 | — |
| 等人确认 | 待确认、已确认、已驳回 | 等待审批、等待确认、待授权、需审批 |
| 配置是否验证过 | 待验证、已验证、验证失败 | 待评测、未验证、未验收、试运行失败 |
| 设备动作的结果 | 已生效、未执行、结果未知、已撤销、已过期 | 配置已核验、结果待核实、撤销待核验 |
| 该有的数据没有 | 无数据 | 不可观测、未观测到、尚未观测、未获取、缺测 |
| 数据不全 | 不完整 | 观测不足、完整性不足 |
| 证据不够，下不了结论 | 证据不足 | 无法判定、无法确认 |
| 研判结论 | 真实攻击、可疑、误报、证据不足 | — |
| 功能状态 | 未提供、未启用、未配置、不支持 | 不可用、未接入 |
| 服务出错 | 服务异常，请稍后重试 | 暂不可用、暂时不可用、不可用 |

- 健康的具体原因写成一眼能懂的短语：磁盘空间不足、CPU 占用高、内存占用高、丢包率高、指标不全。
- 没有数据的单元格显示“无数据”或“—”，不显示 0，也不解释成“正常”。
- 指标旁的小字说明数字补充、单位或缺测原因。
- 协议可见性、会话完整性这类专业取值（例如“仅元数据”“缺少握手”）不在本表范围内，沿用各自的设计文档。

### 密度与布局

- 页面标题单行，动作在右侧。指标项横向排列，空间不足时项内换行。筛选标签与控件同行。
- 同一位置不重复表达：功能页签与页面标题同名时不再单独显示说明行。
- 1024px 宽度下顶栏不折行：面包屑只留当前页名称，用户名单行省略。
- 弹窗正文的左右边缘与标题、底部按钮对齐。

### 档位

界面字号使用 12、13、14、16、20、24px，字重使用 400、500、600，圆角使用 4、6、8px。弹窗圆角为 12px，数据包字节选中圆角为 2px。原型登录页的展示标题使用独立字号。

### 一套组件（尚未落地）

- 外壳、筛选、表格、分页、状态标签、指标条、状态面板只在 `web/packages/shared/` 实现一份，主控平台、采集器和原型共同使用，本规范是唯一依据。
- 工程端当前版本未提供的工作区不在侧栏显示，只在“系统设置”的功能目录里列出并标明未提供。

## Colors

纯浅灰工作区与白色导航、指标和面板支撑持续阅读；表头与辅助区域使用灰底；按钮、链接、选中项和提示采用组件默认算法与靛蓝基础色，图表延续共享系列色。精确值以 frontmatter 为准；这里只说明用途。

### Primary

- **强调蓝**（primary）：组件主色、键盘焦点轮廓和图表，取靛蓝 `#2f54eb`。
- **动作蓝**（action）：主按钮背景，与主色相同；与链接、选择控件共用同一主色来源。
- **动作悬停与按下**（action-hover、action-active）：主按钮交互背景；与 primary-hover、primary-active 同源，由默认算法生成。
- **链接蓝**（link）：记录入口、普通链接、选中导航与页签文字；沿用组件默认主色，不再独立指定另一套蓝色。
- **文本选择字色**（selection-text）：与默认派生的浅色文本选择底成对使用，保持选中文本可读。

### Secondary

- **成功绿**（success）、**健康绿圆点**（success-dot）与**成功浅底**（success-surface）：确定的成功或健康状态。文字和圆点使用各自取值。
- **关注琥珀**（warning）、**关注琥珀圆点**（warning-dot）与**关注浅底**（warning-surface）：当前风险、等待核对、异常状态或会影响操作的限制；组件警示圆点使用警示基础色，业务标签文字使用更深的警示文字色。
- **风险红**（danger）、**风险红圆点**（danger-dot）与**风险浅底**（danger-surface）：严重风险与明确失败。
- **信息文字**（info-text）与**信息浅底**（info-surface）：信息提示正文使用中性深灰，底色和边框是纯灰，图标与信息状态圆点取主色。
- **中性标签底**（status-surface）与**中性标签文字**（status-text）：纯灰背景承载不需要成功、警示或风险强调的业务状态。
- **规则变量紫**（syntax-variable）、**规则选项棕**（syntax-option）与**规则数字玫红**（syntax-number）：规则编辑器中的变量、选项名与数字。关键词使用 syntax-keyword，字符串使用 syntax-string，注释使用辅助灰，运算符使用正文色；语法着色不表示规则已经通过引擎验证。

**The 文字与颜色 Rule.** 颜色辅助定位状态；严重级别、生命周期、执行结果与证据缺口必须同时有可读文字。结果未知、不完整与无数据写出原因，只有满足对应业务状态的记录才呈现成功含义。

**The 语义提示 Rule.** 静态业务边界使用低强调的信息提示；警示色表达当前风险、异常状态或会影响操作的限制，不将所有页面说明标为警示。

### Tertiary

- **图表青**（teal）、**图表紫**（violet）、**图表橙**（chart-orange）与**图表中性蓝**（chart-neutral）：与操作蓝组成普通图表的系列色，顺序由 chartPalette 统一提供。
- **图表浅网格**（chart-grid）：普通图表的背景刻度线，避免与数据曲线争夺注意力。
- 图表颜色用于区分系列，不替代图例、数值、曲线形状或业务状态文字。拓扑节点和关系沿用同一调色板，并以名称、箭头和图例说明含义。

### Neutral

- **面板白**（surface）：导航、顶栏、指标、表格、表单与详情容器。
- **工作区浅灰**（workspace）：控制台与认证入口的纯浅灰背景；面板通过底色与边框形成层次。
- **分隔线浅灰**（line）：面板边框、工具栏、字段组与记录区域的结构分隔。
- **控件边界浅灰**（control-border）：正常输入、选择和默认按钮的轻量轮廓；复选框、单选框使用独立 selection-border，焦点与错误使用对应语义色。
- **正文墨蓝**（text）、**记录文字**（record-text）：正文及密集记录；**辅助灰蓝**（muted）用于业务说明、提示与元数据。
- **字段标签**（field-label）：筛选条件及表头；**占位灰蓝**（text-placeholder）只说明输入预期，不替代字段名称。
- **表头浅灰**（table-header）、**记录悬停底**（row-hover）：表头和辅助区域使用纯灰底，帮助扫描和追踪当前行。
- **选中导航底**（nav-selected）、**选中页签底**（tab-selected）：以纯灰分别标识侧栏位置与当前工作页面。
- **文本选择底**（selection-surface）：原生文本选择及框架选中项悬停使用的纯灰背景，与文本选择字色配对。

框架背景取值与调色板角色保持一致：

| Map Token | 取值来源与用途 |
| --- | --- |
| colorPrimaryBg | nav-selected；表格选中行、下拉选项等主色派生选中背景。 |
| colorPrimaryBgHover | selection-surface；主色派生选中背景的悬停状态。 |
| colorInfoBg | info-surface；普通信息提示底色。 |
| colorInfoBgHover | nav-selected；信息提示背景的悬停状态。 |
| colorInfoBorder | 与分隔线相同（`#e5e5e5`）；普通信息提示边框。 |

成功、警示、危险三类提示的底色和边框也在主题文件里显式给出（`componentSurfaces`），不再由基础色自动派生。

### 独立深色工作区

态势大屏使用 screen 系列：**大屏深色工作区**（screen-workspace）、**大屏内容面板**（screen-panel）、**大屏指标背景**（screen-metric）形成三层无色相深灰底；**大屏分隔线**（screen-line）划分区域。**大屏正文**（screen-text）和**大屏说明**（screen-muted）保持浅色可读层级，**大屏数值**（screen-number）使用高亮蓝青色，**大屏入口**（screen-link）提供文字链接。

大屏图表依次使用**图表蓝**（screen-chart-blue）、**图表青**（screen-chart-teal）、**图表紫**（screen-chart-violet）与**图表琥珀**（screen-chart-amber），由 `screenChartPalette` 统一提供。高危指标用大屏风险玫红（screen-danger），关注指标用大屏琥珀（screen-amber）。状态标签保留文字、圆点和浅底。

大屏图表背景对比度至少为 3:1。色弱回归将线性 sRGB 分别投影到 Machado 模型表 A.1 中强度 1.0 的红、绿色觉缺失模拟，再计算相邻系列的 Oklab 欧氏距离。环形图核对首尾相邻扇区，项目色差门槛为 0.08。 [Machado 模型表 A.1](https://www.inf.ufrgs.br/~oliveira/students_dissertations/Masters/Gustavo_Machado_Masters_thesis_UFRGS_2010.pdf) [Oklab 转换](https://bottosson.github.io/posts/oklab/)

**The 色源一致 Rule.** 业务色从主题文件取用；共享样式使用根级 CSS 变量，图表使用同一调色板，挂载到 body 的浮层与静态截图目录保持角色颜色一致。派生色带只用于设计面板，不进入界面色源。

## Typography

**正文字体：** 声明的系统字体栈，优先使用操作系统界面字体，中文回退到 PingFang SC、Microsoft YaHei；不依赖远程字体。
**技术字体：** 技术内容使用 ui-monospace、SFMono-Regular、Menlo、Consolas 的等宽回退。

**字体特征：** 正文和字段保持清晰、克制。字重与字号区分任务层级，等宽字体定位字节、查询和编号；数值比较使用 tabular-nums，而非通过缩小业务文字容纳数据。

### Hierarchy

| 角色 | 用途与现行边界 |
| --- | --- |
| page-title | 普通工作区标题；较紧凑 PC 宽度的局部调整见 Layout。 |
| detail-title | 详情对象名称；不承担页面入口的展示标题。 |
| section-title | 详情分节和较强的内容分组。 |
| panel-title | 图表面板、表格工具栏等容器名称。 |
| body / button | 组件主题正文与普通主按钮；按钮行高经过实际采样。 |
| record-link | 可进入详情的记录名称。 |
| field-label / caption | 字段、表头、业务说明与辅助元数据。 |
| status-label | 小状态标签，文字与圆点同时出现。 |
| technical | 查询、代码、数据包字节与偏移等原始证据统一用 12px 等宽字体。 |
| rule-editor | Suricata 规则编辑内容；13px 等宽字体、1.65 行高，不改变通用技术内容字号。 |
| metric / metric-dark | 普通指标数值为 20px，深色大屏指标为 24px。 |

普通表格正文是局部规则（13px），不是 App 主题正文（14px）的替代值。详情名称继承所在标题的字重与行高，不为未显式设置的属性补造 token。

原型主控登录页的介绍标题为 45px，较紧凑桌面为 39px，使用 600 字重、1.45 行高和 -1px 字距。原型采集器登录页的介绍标题为 32px，使用 600 字重、1.4 行高和 -0.2px 字距。登录卡片标题为 24px。报告正文使用 13px 和 1.9 行高。

**The 正文与取证 Rule.** 业务文字使用声明的系统字体栈；原始查询、协议字节和技术标识使用等宽字体，连续数值使用等宽数字。

**The 数值与无数据 Rule.** 容量采用 SI 的 B、KB、MB、GB、TB 等单位，速率采用千进制 bit/s；显式 KiB 等二进制单位保留原义。64 位整数通过整数串与 BigInt 运算保留精度，混合单位按精确数值排序。无数据与真实零值分别展示，写明原因，不填造为零。

## Layout

控制台采用固定侧栏与流动内容区。界面只面向 PC 桌面，最小支持宽度为 1024px，不提供移动端布局、手机导航或触控专用交互。侧栏展开宽度为 220px，折叠为 64px；顶栏高 56px，已访问工作区标签带高 44px。侧栏保持独立纵向滚动；顶栏与已访问标签带分别黏贴在工作区顶部，内容区最大宽度为 1920px。

内容区四侧外沿为 16px，由 page-inset 控制。页面以工作区功能页签（存在多个视图时）、标题及业务说明、适用业务指标、业务边界提示、筛选、工具栏、表格与分页构成阅读顺序。主动作在页面或表格工具区域对齐，次级动作保留较低权重。

共享空间采用六个根级 CSS 变量，对应 frontmatter 的同名 spacing token；默认值以 frontmatter 为准。独立区块保持 12px 间隔，面板主要内容采用纵向 12px、横向 16px。关联动作使用 8px，筛选标签与控件使用 4px，普通表单两列之间使用 12px；全宽字段跨两列。该节奏不要求所有局部值都是 8px 倍数。

| 空间 token / CSS 变量 | 实际用途 |
| --- | --- |
| page-inset / --page-inset | 控制台与采集器内容外沿。 |
| section-gap / --section-gap | 标题、指标、提示、筛选与内容区块的分组距离，筛选面板和表格工具栏的纵向内边距。 |
| panel-inset / --panel-inset | 面板横向内边距、表单字段组底部距离和详情分节距离。 |
| field-gap / --field-gap | 筛选字段、普通表单列、容量字段与采集器配置摘要的横向间隔。 |
| related-gap / --related-gap | 关联动作、功能页签纵向内边距、面板标题底部与详情分节标题下方距离。 |
| label-gap / --label-gap | 筛选标签与控件、指标说明与数值、页面标题与说明的近邻距离。 |

筛选面板与表格工具栏采用同一组 section-gap / panel-inset，分页外沿也与面板对齐。面板标题内边距为 12px 16px 8px，底部说明外边距为 0 16px 12px。普通指标条上下内边距为 8px，每个指标的横向内边距为 16px，同行内容间隔为 10px。表格单元格主题内边距为纵向 12px、横向 14px。输入、按钮及表格沿用各自的高度规则。容器按内容类型应用间距变量。

**The 单一业务视图 Rule.** 每个功能视图只呈现一个业务列表，不同对象通过功能页签或 view 查询参数切换；指标与说明服务于当前数据集。详情中的字段描述表属于对象说明，不计作第二个业务列表。

普通筛选区使用三个字段列加动作列；高级筛选使用四列。概览双栏默认比例为 1.65:1；协议树与载荷工作区默认双栏，字节区域保持自身横向滚动。独立大屏默认三列图表。

PC 宽度区间的布局行为如下。1024px 是最小支持宽度，不再设更窄的断点；低于该宽度的页面保留内部滚动，不做移动端重排。

| 视口规则 | 已实现的布局行为 |
| --- | --- |
| ≥1650px | 内容外沿、面板内边距与区块间隔沿用默认变量；大屏图表高度相应调整。 |
| 1200–1649px | 默认布局：普通筛选三列加动作列，概览双栏，大屏三列图表。 |
| 1181–1199px | 探针筛选转为两列，动作独占一行；其余区块沿用默认布局。 |
| 1024–1180px | 在上一档基础上，普通筛选动作独占一行，字段间隔保持 12px；协议与载荷改为上下区域；大屏变为两列。 |

详情与操作弹窗采用内部滚动，内容容器为纵向弹性布局，默认最大高度为 `calc(100dvh - 128px)`；屏高不超过 700px 时距顶 20px、最大高度为 `calc(100dvh - 48px)`。标题与底部按钮不收缩，正文吸收可用高度并单独滚动。操作表单、记录表单和节点检查器的字段组底部距离取 panel-inset；详情分节及底部操作区的上方距离也取 panel-inset，底部操作区分隔线上方内边距取 section-gap。详情证据摘要内边距与底部间隔为 12px；四列之间保留局部 10px 间隔，标签与值保留局部 7px 距离。

工程 PCAP 重放表单与任务详情使用局部宽度（780px）。任务详情正文最大高度为 68vh 并保持内部滚动；样本表、任务表和命中明细各自在容器内横向滚动。摘要与标识使用等宽字体并允许任意位置折行。原始执行回执保留换行、内部滚动与局部最大高度（320px），采用 execution-receipt 的底色、字体、圆角和内边距；这些局部尺寸不改变原型的弹窗或通用布局规范。

采集器继承相同的页面、面板与字段变量。配置摘要采用 12px 16px 内边距和 12px 字段间隔；内容分节采用 0 16px 16px 内边距。关联动作之间为 8px，独立分节之间为 12px。采集器表单正文保持内部滚动，最大高度为 65vh；正文内边距为 2px 3px 12px，字段组底部距离取 panel-inset，底部操作区上下内边距为 12px。

大屏嵌入布局的外沿取 panel-inset，指标栏上下内边距也取 panel-inset；标题、指标、图表区块保持 12px 间隔，宽屏不放大这些距离。全屏大屏的外沿仍为局部 30px，不推广为控制台页面外沿。认证入口保持独立介绍区和卡片布局，仅表单字段组底部距离取 panel-inset。

页面原型图库使用独立 HTML 样式，页头与主区内边距为纵向 16px、横向 4%，卡片间隔为 12px、分组底部间隔为 24px，边界入口容器内边距为 16px。图库保持三列，1100px 及以下为两列，650px 及以下为单列；图库属于评审工具，其列数与断点规则不进入控制台布局，也不受控制台 1024px 最小支持宽度约束。

七档几何审计记录支持其检查范围内的布局边界；代表截图另核对检索、规则编辑、重放与采集器操作。几何检查不替代全部主控功能视图、图库图片或未捕获状态的人工视觉、可访问性与性能验收。低于 1024px 的显示结果不在支持范围，不作为缺陷受理。

顶栏“原型状态”下拉属于评审工具，不能成为正式生产导航或权限判断的视觉规范。

原生滚动条使用浅中性灰滑块（`#e0e3e9`）与透明轨道，沿用浏览器提供的操作方式。探针、PCAP 与通用详情的说明字段在 PC 宽度下保持双列；原本为单列的完整性内容继续单列。该配置记录已实现行为，不扩大验收范围。

## Elevation & Depth

控制台以色调层次和细边框为主。普通白色内容面板不使用独立投影；工具栏、字段组与证据区域通过分隔线保持组织关系。交互反馈和覆盖层保留其实际阴影，不把它们推广到所有内容面板。

### Shadow Vocabulary

- **主按钮反馈**：明亮蓝底、白字和 8px 圆角，下沿采用 2px 的低透明度同色投影；悬停与按下分别采用独立蓝色。输入焦点使用 2px 半透明蓝色外沿，不覆盖错误与禁用状态。
- **页签选中线**：`inset 0 -2px 0 var(--primary)` 是位置标记，不是面板抬升。
- **剧本选中节点**：`0 0 0 2px var(--selection-surface)` 表达纯灰选中边界；它不表示任务已经运行或执行成功，也不作为内容面板的阴影规则。

主按钮使用 `0 2px 0 rgba(93, 135, 255, 0.12)`，默认按钮使用 `0 2px 0 rgba(41, 52, 61, 0.025)`。弹窗、浮层及组件内部的其余阴影由固定 Ant Design Vue 主题生成，未独立采样，不在此记录未核实的值。

**The 平面工作区 Rule.** 控制台面板依靠底色、细边框与间距区分；投影用于控件反馈，不为每个内容面板制造浮起效果。

## Shapes

常规控件和面板使用 8px 圆角，嵌套容器使用 6px，标签使用 4px。弹窗外壳使用 12px，数据包字节选中使用 2px。状态标签同时保留圆点和文字。

结构边框通常为 1px。表格面板裁切自身边缘，表格与字节内容的横向滚动保留在内部。证据摘要、代码块和嵌套内容沿用相应容器圆角。

## Components

主控平台、采集器和交互原型共用 `web/packages/shared/src/theme.ts` 与 `controls.css`；原型主题仅重新导出共享定义。工作区、导航、面板和表头沿用现有白灰值，控件选中项使用组件默认派生色。主动作采用 `#2f54eb`，正文使用中性深灰 `#29343d`；说明文字与禁用内容各自使用独立语义色。输入框、数字输入、选择器、日期和密码控件由 Ant Design Vue 统一派生状态，不使用常态边框覆盖错误、悬停或焦点。

表单标签使用 14px 常规字重，帮助与校验文字使用 12px、1.65 行高。弹窗标题为 20px，底部操作区以细分隔线与内容区区分。长表单在内容区滚动，决策策略的关闭、校验与保存保持可见。决策表单按基本信息、判断条件、模型与执行范围、表达式与保护范围组织。

### Buttons

主按钮表达可执行的主要动作，主题高度为 34px；背景、文字、圆角与内边距见 button-primary。悬停与按下背景分别采用 button-primary-hover、button-primary-active；文字保持面板白。记录链接保持透明背景、13px 字号、500 字重和零内边距，悬停出现下划线；链接与记录入口的下划线偏移为 3px。检索示例按钮为白底细边框，悬停时边框与文字转为主色；它是辅助输入入口。

按钮与链接的键盘焦点采用源码中的 2px 主色轮廓及 3px 外偏移。主色悬停与按下由默认算法生成；其余 Ant 禁用与内部焦点反馈继续由固定组件版本及主题生成，不补造没有独立采样的状态色。

主按钮实际过渡为 all、0.2s，缓动为 cubic-bezier(0.645, 0.045, 0.355, 1)。选中菜单项的 border-color、background、padding 过渡分别为 0.3s、0.3s、0.2s，缓动分别为 ease、ease、cubic-bezier(0.215, 0.61, 0.355, 1)。不存在独立的布局宽度或主区边距动画规则。

### Inputs / Fields

字段名称与控件分开，Ant 纵向表单标签为 14px、常规字重；帮助说明为 12px 并解释单位、业务条件与影响。筛选栏标签仍为局部 12px。普通输入、选择和数值控件沿用 App 主题的高度、圆角与正文；正常控件边界使用 control-border，选择器与默认按钮也保持这一边界；复选框、单选框沿用组件默认边界与状态。未独立采样的 Ant 悬停、禁用与内部焦点状态继续由固定主题派生。

筛选标签与控件的 4px 距离用于关联同一条件；普通表单列间隔为 12px，字段组底部距离取 panel-inset。Ant 表单内部标签、帮助与校验反馈仍由既有组件规则组织，不将筛选区的标签距离推广到全部表单内部。

常态主按钮白字和白底主色链接均为 5.85:1。导航选中文字为 5.13:1。成功和警示标签文字分别为 4.64:1 和 4.97:1。这些组合与其余正文、业务文字和规则语法一起执行 4.5:1 检查。普通输入白底占位文字为 3.36:1，控件轮廓为 1.41:1，两项单独记录。禁用控件使用独立语义色。占位提示只补充字段说明。输入、文本区域与可编辑内容的光标使用主色，原生文本选择使用 selection 系列配色。

开关的未选中、悬停、禁用与已选中状态均使用组件默认算法，保留可读的业务状态名称，不由局部样式重画背景。

检索表达式编辑框是已实现的独立样式：浅灰底、细边框、左侧行号、等宽内容，文本区域内边距为 9px 12px、13px 字号、1.9 行高；行号采用辅助灰，帮助对齐且保持可读；其内部不再叠加第二层边框或焦点投影。侧车保留这一实际输入片段，不推定普通 Ant 输入框的所有派生态。

规则编辑器使用真实 CodeMirror 6，支持行号、撤销、折行、语法高亮和可点击错误定位。白底编辑区域采用 1px 控件边界、6px 圆角；焦点为 2px 主色轮廓及 2px 外偏移。内容纵向内边距为 8px，滚动区域最小高度为 180px、最大高度为 340px；行号为表头浅灰底与辅助灰文字。底部状态区采用 12px 字号及 8px 12px 内边距，最多列出五条可定位问题，其余在编辑器标记处查看。

**The 规则诊断边界 Rule.** 本地基础检查限定 900 KiB 的 alert 规则，核对七个头字段、引号、括号、末分号、SID 范围与重复及 rev；基础检查通过不等于完整语法、语义或引擎兼容通过。未知关键词、变量与兼容性必须由选定探针原生 Suricata -T 验证，原型候选与检测报告仍为固定合成示例。

表单在本地执行必填与业务校验。置信度保存在 0–1，列表、详情与导出转换为百分比；表单明确说明单位。生命周期按对象定义，影子、审批与自动执行单独选择。

### Chips

共享状态标签由短文字与 6px 圆点组成，间隔 5px。中性、信息、成功、警示、危险和严重六种色调分别定义背景、文字和圆点。告警严重度、告警处理、探针连接、探针健康与任务执行各有自己的状态映射。[共享状态标签](web/packages/shared/src/components/StatusTag.vue) · [业务色调映射](web/packages/shared/src/statusTones.ts)

租户使用启用／停用；决策策略使用启用／待验证／停用。严重级别、处理阶段与运行模式各自使用对应名称。结果未知、不完整与无数据保留原因，不通过颜色暗示确定成功。

### Cards / Containers

白色指标条用竖线分隔各项，数值、单位及原因放在同一项内。数值默认使用正文色，仅正数的风险指标用警示色或危险色。大屏指标使用深色底和亮青色数值，高危与关注数值分别使用大屏玫红和琥珀。配置类页面按当前对象提供有业务意义的指标。[共享指标条](web/packages/shared/src/components/MetricBar.vue)

**The 业务指标 Rule.** 指标必须对应当前对象与可解释的统计口径。探针指标来自同一筛选数据集与健康阈值；离线、心跳超时和执行角色不显示推定正常的采集指标。当前范围没有捕获遥测时，观测镜像流量显示“—”及原因，不能以零流量代替无数据。态势总览与态势大屏的探针指标使用探针列表的同一设备快照和健康阈值，按各自网络域或展示范围筛选，加载与失败时不展示指标；其他业务图表仍为合成场景，不表示所有模块已实现联动统计。

表格工具栏先显示记录类别与数量，再提供适用动作。表头使用浅灰底、12px 字号、500 字重；正文为 13px，悬停行采用独立浅色背景。记录链接及等宽编号组成行身份；状态列和操作列不与名称混写。长日期与技术字段允许表格内部滚动。

### 认证入口

认证页面使用工作区浅灰背景（workspace）。白色卡片使用分隔线浅灰边框（line）和 8px 圆角。介绍标题取链接蓝。

### Navigation

桌面侧栏按工作任务组织导航工作区，保留分组与子菜单，菜单行高为 41px；当前条目使用 nav-selected 背景与链接蓝文字。工作区和功能视图的数量以 `web/packages/shared/src/navigation.json` 与[页面清单](prototype/public/page-manifest.json)为准；107 项需求仍由相应功能视图与对象详情承载。

已访问工作区标签与当前工作区的功能页签各自承担导航层级。已访问标签为 36px 高，最多保留五个工作区及页面目录入口；当前工作区使用纯灰底、蓝色文字和底部选中线，悬停使用表头浅灰底，标签带允许内部横向滚动。功能页签位于内容区，仅在工作区存在多个视图时显示；现行分组最多七个页签，文字为 13px，纵向内边距取 related-gap（8px），页签区域与后续内容保持 12px 距离；功能与详情页签的悬停文字使用链接蓝。

顶栏呈现当前位置、租户范围与通用入口，并以单一下拉选择原型评审状态；PC 宽度下租户选择始终可见。侧栏折叠按 Layout 中的源码断点执行。

**The 工作任务连续 Rule.** 同一对象的列表、运行状态、依据与操作在所属工作区和对象详情中衔接；避免为重复数据集或同一任务的下载步骤建立平行入口。

平台工程在探针管理中分别呈现“探针列表”和“任务记录”（`/sensors/list`、`/sensors/tasks`），检测规则分别呈现“规则包”“重放样本”和“重放任务”（`/detection/rules/packages`、`/detection/rules/samples`、`/detection/rules/tasks`）。采集器工程将“网卡列表”“采集配置”“重放样本”和“任务记录”分开（`/network/interfaces`、`/network/capture`、`/rules/samples`、`/rules/tasks`）；保存采集目标表示待应用，不表示已修改操作系统网络。

原型检测规则的“重放样本”和“重放任务”与工程使用相同规范路径，页面目录中的 `/page/rule-samples`、`/page/rule-tests` 跳转至这些路径。采集器原型的升级与维护目标页签分别使用 `view=system`、`view=audits`；它们不是工程采集器路径。三端均使用 History 路由，保留安全的同源登录返回路径；规范路径支持刷新及浏览器前进／后退，原型目标页签的缺省或非法 view 回到默认视图。未知页面进入 404；部署入口的 SPA 回退见[工程前端说明](web/README.md)。

### 详情、证据与业务状态

详情对象名称、编号、租户范围与状态首先说明当前记录；相关依据和操作继续在同一弹窗中。身份与时间属于当前对象，不能借用其它记录的确定结论。底部操作必须能通过弹窗内部滚动与键盘焦点进入可见区。只有一个详情分节时隐藏重复页签。

探针管理的列表、资源、心跳、健康与详情共用同一设备记录；“基本信息”“运行状态”“采集与版本”“运行记录”在对象详情内组织。健康阈值同时影响列表判断与详情状态，仅保存在当前原型会话，不表示向探针下发配置。

PCAP 任务详情串联任务信息、会话完整性与下载授权；真实文件、完整性和授权条件尚未满足时保持下载禁用，合成证据清单的导出与真实 PCAP 下载各自标明含义。操作记录统一从审计日志工作区进入。

通信证据同时呈现捕获范围、会话完整性、协议结构和原始字节。选中字节使用主色背景与白色文字，并保留偏移；字节表示与尝试解码各自说明来源和限制。TLS 密文不能显示为推定明文。

设备接受、配置回读与效果观察分别展示；缺少关联任务、回读或观测证据时说明未知及所需核对。留存影响同时展示当前期限、目标期限、变更依据和保全排除；业务数据默认 180 天不替代运行 TTL 的含义。

### 离线重放结果与任务追溯

检测结果先说明重放是否完成及是否命中，再呈现包数、命中数、耗时和当前样本／规则摘要。完成结果使用低强调的信息提示，执行失败使用错误提示；未命中不呈现为流量安全。采集器将指定规则标为“本次输入规则”，平台显示“指定规则包”与修订，登记规则来源统一标为“登记规则快照”。

命中明细以表格呈现 SID／修订、规则名称、地址、数据包序号和捕获时间。任务标识、探针身份及任务起止时间放入默认折叠的“任务追溯”；原始结果放入默认折叠的“执行回执”，通过原生展开控件保留键盘入口。其他任务仍默认展开任务追溯。检测限制、样本截断及握手未验证直接说明结果影响，不能用装饰性成功指标替代。

重放属于现有工作区的连续任务：平台在规则管理中组织样本与重放任务，采集器在网络与采集中组织样本及本地／平台任务。任务读取失败且已有记录时保留上次成功读取的状态，并显示“任务状态更新失败”及核实提示；首次读取失败显示错误状态。连续三次读取失败停止自动刷新，保留手动重试；错误不能进入“暂无执行任务”。

### 空状态、加载与边界

无数据说明当前没有记录的业务原因并给出下一步。无结果判断同时包含关键词、状态、健康、网络域及高级字段；存在筛选条件时提供“清除筛选”，避免将匹配失败解释为未接入或无业务记录。加载保持页面身份和查询条件；加载失败保留重试入口。权限不足说明对象或租户范围的访问边界。这些状态不能合并成同一张“没有风险”的提示。

状态容器为白色面板，原型的默认最小高度为 340px，工程共享状态面板为 280px；使用居中的图标、标题、说明和动作。图标来自既有组件或内联 SVG，不使用文本字形冒充操作图标。

### 动态与减少动态效果

动态用于控件反馈、菜单和弹窗状态。用户偏好减少动态效果时，源码将 animation-duration 与 transition-duration 设为 0.01ms、动画迭代次数设为 1，并恢复自动滚动。截图 capture-mode 完全冻结动画和过渡；它是评审捕获规则，不是新的业务状态。

侧车片段保持可独立渲染的 HTML/CSS，颜色与代码样式来自已实现组件；不包含 Vue 运行时、本地提交行为或生产能力演示。

## Do's and Don'ts

### Do:

- **Do** 保持导航、指标和面板白色，工作区与认证背景使用纯浅灰，表头、辅助区域与选中项采用纯灰底，沿用用户指定的后台布局。
- **Do** 将操作蓝用于主要动作，链接蓝用于记录与导航文字，状态色与浅底配对，并保留文字说明。
- **Do** 为每类对象使用对应的生命周期；运行模式、设备接受、配置回读与效果观察分别展示。
- **Do** 使来源、时间、租户范围、完整性与证据缺口绑定当前记录；缺少依据时说明尚不可确定的内容。
- **Do** 保留有数据、无数据、详情、操作、加载和失败之间的语义差异，并提供业务原因或下一步。
- **Do** 在普通输入框与选择框中保持占位提示可读，使用可辨识的正常控件边界，禁用控件保留独立语义。
- **Do** 以 0–1 保存置信度，列表、详情与导出使用百分比；表单说明单位。
- **Do** 让表格在自己的容器内横向滚动，并保留可见的操作出口。
- **Do** 通过工作区页签与对象详情衔接相关任务，共用探针记录、健康口径与任务身份。
- **Do** 只展示适用的业务指标，静态边界说明使用低强调的信息提示，警示提示表达当前风险或限制。
- **Do** 将 180 天业务留存、旁路可见性、TLS 密文与合成数据说明作为用户理解当前结果所需的边界信息。
- **Do** 在离线重放详情中先呈现检测结论、包数、命中数与耗时，任务身份、时间和原始回执使用折叠追溯区域。
- **Do** 保持一个视图一个业务列表，使用功能页签和可恢复的 view 地址衔接样本与任务。
- **Do** 以整数串和 BigInt 保留大计数精度，容量与速率使用明确单位，无数据与零值分别说明。

### Don't:

- **Don't** 用空状态、加载失败或权限不足替代彼此的业务含义。
- **Don't** 用其它记录的样本、固定成功回执或推定解密结果填补当前对象的证据缺口。
- **Don't** 将影子、审批与自动执行写成生命周期，或将设备接受显示为配置已生效与效果已验证。
- **Don't** 将原型评审状态下拉、原型本地提交、示例回复或合成指标写成生产能力承诺。
- **Don't** 把大屏的深色工作区配色扩散到普通表格与表单页面，或为平面面板增加装饰性厚重阴影。
- **Don't** 为控制台、认证入口、辅助区域或选中项使用浅蓝背景；蓝色保留在动作、链接、图表、文字和焦点等前景语义。
- **Don't** 传承未被现行界面采用的标题前装饰标签样式，或把登录入口的局部展示尺寸扩散为通用页面标题。
- **Don't** 把侧车合成色带、未独立采样的组件派生态或局部 PC 宽度检查当作已经确认的全局 token 或完整验收。
- **Don't** 将未命中视为流量安全、将登记规则快照视为必然正在运行的实时规则，或将装载和重放通过视为自动发布资格。
- **Don't** 将基础编辑诊断写成完整 Suricata 解析或发布资格，或将原型固定候选写成真实模型结果。
