---
name: "星烽 StarBeacon"
description: "以记录、证据与受控操作为中心的安全运营控制台设计系统。"
colors:
  primary: "#096bff"
  primary-hover: "#075de3"
  primary-active: "#074ab8"
  link: "#0759d5"
  surface: "#ffffff"
  workspace: "#f7f7f7"
  line: "#e8e8e8"
  control-border: "#7b8fae"
  text: "#22334d"
  muted: "#526581"
  text-placeholder: "#596b84"
  field-label: "#496381"
  record-text: "#344c70"
  table-header: "#fafafa"
  row-hover: "#fafafa"
  nav-selected: "#f0f0f0"
  tab-selected: "#f3f3f3"
  selection-surface: "#e9e9e9"
  selection-text: "#074ab8"
  success: "#087a43"
  success-dot: "#079454"
  warning: "#a65a00"
  warning-dot: "#cd7100"
  danger: "#cc2640"
  danger-dot: "#e83855"
  status-surface: "#f3f3f3"
  status-text: "#526581"
  success-surface: "#eff8f2"
  warning-surface: "#fff7e9"
  danger-surface: "#fff0ef"
  info-surface: "#f4f4f4"
  info-text: "#095ace"
  teal: "#0095ad"
  violet: "#8950e9"
  chart-orange: "#d97900"
  chart-neutral: "#6d83a5"
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
  screen-violet: "#b298ff"
  screen-amber: "#ffd174"
  screen-danger: "#ffa0b2"
typography:
  page-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "24px"
    fontWeight: 650
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
    fontSize: "15px"
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
    fontSize: "11px"
  status-label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "11px"
    lineHeight: 1.5
  technical:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "12px"
  metric:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif"
    fontSize: "25px"
    fontWeight: 650
    lineHeight: 1.25
rounded:
  control: "6px"
  panel: "8px"
  tag: "4px"
  nested: "5px"
spacing:
  page-inset: "16px"
  section-gap: "12px"
  panel-inset: "16px"
  field-gap: "12px"
  related-gap: "8px"
  label-gap: "4px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "5px 15px"
    height: "34px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-primary-active:
    backgroundColor: "{colors.primary-active}"
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
  workspace-tab:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "5px 5px 0px 0px"
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
    padding: "3px 7px"
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
    backgroundColor: "{colors.info-surface}"
    textColor: "{colors.info-text}"
  metric:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.link}"
    typography: "{typography.metric}"
  metric-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.danger}"
  metric-warning:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.warning}"
  metric-success:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.success}"
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
    rounded: "2px"
    padding: "1px 1px"
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

本系统从已交付的 Vue 3、TypeScript 与 Ant Design Vue 原型提取；原型全部使用合成数据，操作仅改变本地内存。设计说明不代表后端、身份、模型、MCP、设备访问、数据清理或性能已经验收。

**Key Characteristics:**

- 白色导航、指标与结构面板，纯浅灰工作区与认证背景；明亮操作蓝与深蓝链接分别表达动作和记录入口。
- 桌面优先，表格、表单、详情和操作弹窗使用一致的空间与状态语言。
- 系统中文字体、等宽技术字段和等宽数字分别承担阅读、取证与数值比较。
- 证据不足、不可观测、运行模式与生命周期各自保持独立含义。

颜色取值依据为 [主题文件](prototype/src/theme.ts)，共享样式依据为 [实际样式](prototype/src/styles.css)。[应用入口](prototype/src/main.ts)在挂载前把调色板写入根级 CSS 变量，覆盖主平台、采集器和挂载到 body 的弹窗、通知；[应用主题](prototype/src/App.vue)将同一配置交给 Ant Design Vue。组件配置按固定版本 4.2.6 的实际接口使用 Menu.colorItemText、colorItemBgSelected 等取值；Map Token 显式指定 colorPrimaryBg、colorPrimaryBgHover 和 colorInfoBg、colorInfoBgHover、colorInfoBorder，表格选中行、下拉选项与信息提示据此使用纯灰背景。其余未独立核实的组件派生态继续由该版本的主题生成。

设计依据为用户指定布局、产品约束、实际代码和截图。配色回归脚本核对 49 组文字组合（对比度至少 4.5:1）、16 组控件与图形组合（至少 3:1）及静态截图目录的角色颜色一致性；这些检查不替代所有视图、交互状态和可访问性的验收。配色收尾评审覆盖 13 张代表截图及指定源码；间距收尾评审覆盖 19 张代表截图、四种视口及指定样式，结论分别仅适用于各自范围。图库图片的批量来源同步不代表全部图片已获视觉评审。侧车的八阶色带是设计面板使用的 OKLCH 派生预览，不属于界面 token。

## Colors

纯浅灰工作区与白色导航、指标和面板支撑持续阅读；表头、辅助区域、选中项及普通信息提示使用无蓝色调的灰底，亮蓝动作、深蓝链接、鲜明状态色和图表色共同构成清晰层次。精确值以 frontmatter 为准；这里只说明用途。

### Primary

- **操作蓝**（primary）：主按钮、焦点轮廓、选中字节和信息状态圆点；白色文字置于操作蓝按钮上。
- **主色悬停**（primary-hover）、**主色按下**（primary-active）：主题文件明确指定的动作与链接反馈。
- **链接蓝**（link）：记录入口、普通链接、选中导航与页签文字；与动作背景分别取用，保证浅色底上的文字可读。
- **文本选择字色**（selection-text）：与纯灰文本选择底成对使用，保持选中文本可读。

### Secondary

- **成功绿**（success）、**健康绿圆点**（success-dot）与**成功浅底**（success-surface）：确定的成功或健康状态。文字和圆点使用各自取值。
- **关注琥珀**（warning）、**关注琥珀圆点**（warning-dot）与**关注浅底**（warning-surface）：当前风险、等待核对、异常状态或会影响操作的限制；Ant 警示主题使用圆点色，警示标签文字使用文字色。
- **风险玫红**（danger）、**风险玫红圆点**（danger-dot）与**风险浅底**（danger-surface）：严重风险与明确失败。
- **信息蓝文字**（info-text）与**信息灰底**（info-surface）：研判等信息状态及普通信息提示使用纯灰背景；信息文字和圆点分别取信息蓝文字与操作蓝。
- **中性标签底**（status-surface）与**中性标签文字**（status-text）：纯灰背景承载不需要成功、警示或风险强调的业务状态。

**The 文字与颜色 Rule.** 颜色辅助定位状态；严重级别、生命周期、执行结果与证据缺口必须同时有可读文字。未知、不完整与不可观测写出原因，只有满足对应业务状态的记录才呈现成功含义。

**The 语义提示 Rule.** 静态业务边界使用低强调的信息提示；警示色表达当前风险、异常状态或会影响操作的限制，不将所有页面说明标为警示。

### Tertiary

- **图表青**（teal）、**图表紫**（violet）、**图表橙**（chart-orange）与**图表中性蓝**（chart-neutral）：与操作蓝组成普通图表的系列色，顺序由 chartPalette 统一提供。
- **图表浅网格**（chart-grid）：普通图表的背景刻度线，避免与数据曲线争夺注意力。
- 图表颜色用于区分系列，不替代图例、数值、曲线形状或业务状态文字。拓扑节点和关系沿用同一调色板，并以名称、箭头和图例说明含义。

### Neutral

- **面板白**（surface）：导航、顶栏、指标、表格、表单与详情容器。
- **工作区浅灰**（workspace）：控制台与认证入口的纯浅灰背景；面板通过底色与边框形成层次。
- **分隔线浅灰**（line）：面板边框、工具栏、字段组与记录区域的结构分隔。
- **控件边界灰蓝**（control-border）：正常输入、选择、默认按钮、复选与单选控件的可辨识边界；结构分隔仍使用分隔线浅灰。
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
| colorInfoBorder | line；普通信息提示边框。 |

局部页面信息提示采用表头浅灰，其余信息提示采用信息灰底；两者均为纯灰表面。

### 独立深色工作区

态势大屏使用 screen 系列：**大屏深色工作区**（screen-workspace）、**大屏内容面板**（screen-panel）、**大屏指标背景**（screen-metric）形成三层无色相深灰底；**大屏分隔线**（screen-line）划分区域。**大屏正文**（screen-text）和**大屏说明**（screen-muted）保持浅色可读层级，**大屏数值**（screen-number）使用高亮蓝青色，**大屏入口**（screen-link）提供文字链接。

**大屏亮蓝**（screen-blue）、**大屏亮青**（screen-teal）、**大屏亮紫**（screen-violet）和**大屏琥珀**（screen-amber）组成 screenChartPalette。高危指标独立取**大屏风险玫红**（screen-danger），关注指标使用大屏琥珀。状态标签继续使用文字、圆点和浅底配对；数据、说明和状态遵循相同的证据规则，深色背景不代表数据实时性或完整性。

**The 色源一致 Rule.** 业务色从主题文件取用；共享样式使用根级 CSS 变量，图表使用同一调色板，挂载到 body 的浮层与静态截图目录保持角色颜色一致。派生色带只用于设计面板，不进入界面色源。

## Typography

**正文字体：** 声明的系统字体栈，优先使用操作系统界面字体，中文回退到 PingFang SC、Microsoft YaHei；不依赖远程字体。
**技术字体：** 技术内容使用 ui-monospace、SFMono-Regular、Menlo、Consolas 的等宽回退。

**字体特征：** 正文和字段保持清晰、克制。字重与字号区分任务层级，等宽字体定位字节、查询和编号；数值比较使用 tabular-nums，而非通过缩小业务文字容纳数据。

### Hierarchy

| 角色 | 用途与现行边界 |
| --- | --- |
| page-title | 普通工作区标题；窄屏局部调整见 Layout。 |
| detail-title | 详情对象名称；不承担页面入口的展示标题。 |
| section-title | 详情分节和较强的内容分组。 |
| panel-title | 图表面板、表格工具栏等容器名称。 |
| body / button | 组件主题正文与普通主按钮；按钮行高经过实际采样。 |
| record-link | 可进入详情的记录名称。 |
| field-label / caption | 字段、表头、业务说明与辅助元数据。 |
| status-label | 小状态标签，文字与圆点同时出现。 |
| technical | 查询、代码和原始证据；数据包字节与偏移在局部取证视图中使用更紧凑的字号。 |
| metric | 普通指标数值；较宽和紧凑视口的调整见 Layout。 |

普通表格正文是局部规则（13px），不是 App 主题正文（14px）的替代值。详情名称继承所在标题的字重与行高，不为未显式设置的属性补造 token。

登录入口的介绍文字使用局部字号（45px，较紧凑桌面为 39px）、字重（600）、行高（1.45）和字距（-1px）；登录卡片标题为 22px。该入口沿用用户指定的系统字体，不设独立展示字体规范。报告正文使用 13px、1.9 行高，以正文结构承载解释。

**The 正文与取证 Rule.** 业务文字使用声明的系统字体栈；原始查询、协议字节和技术标识使用等宽字体，连续数值使用等宽数字。

## Layout

控制台采用固定侧栏与流动内容区。侧栏展开宽度为 220px，折叠为 64px；顶栏高 56px，已访问工作区标签带高 44px。侧栏保持独立纵向滚动；顶栏与已访问标签带分别黏贴在工作区顶部，内容区最大宽度为 1920px。

内容区默认四侧外沿为 16px，由 page-inset 控制；899px 及以下为 12px。页面以工作区功能页签（存在多个视图时）、标题及业务说明、适用业务指标、业务边界提示、筛选、工具栏、表格与分页构成阅读顺序。主动作在页面或表格工具区域对齐，次级动作保留较低权重。

共享空间采用六个根级 CSS 变量，对应 frontmatter 的同名 spacing token；默认值以 frontmatter 为准。独立区块保持 12px 间隔，面板主要内容采用纵向 12px、横向 16px；899px 及以下横向内边距为 12px。关联动作使用 8px，筛选标签与控件使用 4px，普通表单两列之间使用 12px；全宽字段跨两列。该节奏不要求所有局部值都是 8px 倍数。

| 空间 token / CSS 变量 | 实际用途 |
| --- | --- |
| page-inset / --page-inset | 控制台与采集器内容外沿；窄屏取 12px。 |
| section-gap / --section-gap | 标题、指标、提示、筛选与内容区块的分组距离，筛选面板和表格工具栏的纵向内边距。 |
| panel-inset / --panel-inset | 面板横向内边距、表单字段组底部距离和详情分节距离；窄屏取 12px。 |
| field-gap / --field-gap | 筛选字段、普通表单列、容量字段与采集器配置摘要的横向间隔。 |
| related-gap / --related-gap | 关联动作、功能页签纵向内边距、面板标题底部与详情分节标题下方距离。 |
| label-gap / --label-gap | 筛选标签与控件、指标说明与数值、页面标题与说明的近邻距离。 |

筛选面板与表格工具栏采用同一组 section-gap / panel-inset，分页外沿也与面板对齐。面板标题内边距为 12px 16px 8px，底部说明外边距为 0 16px 12px；窄屏的横向值跟随 panel-inset。普通指标栏上下内边距为 12px、指标横向为 16px、内部间隔为 4px；窄屏指标块转为两列，各自内边距为 12px。表格单元格主题内边距仍为纵向 12px、横向 14px；输入、按钮高度和表格行高保持既有控件规则。容器按内容类型应用这些变量，不给面板外壳叠加统一内边距。

普通筛选区使用三个字段列加动作列；高级筛选使用四列。概览双栏默认比例为 1.65:1；协议树与载荷工作区默认双栏，字节区域保持自身横向滚动。独立大屏默认三列图表。

| 视口规则 | 已实现的布局行为 |
| --- | --- |
| ≥1650px | 内容外沿、面板内边距与区块间隔沿用默认变量；普通指标放大为 29px，大屏图表高度相应调整。 |
| ≤1199px | 探针筛选转为两列，动作独占一行。 |
| ≤1180px | 普通筛选动作独占一行，字段间隔保持 12px；协议与载荷改为上下区域；大屏变为两列。 |
| ≤899px | page-inset 与 panel-inset 均为 12px；侧栏使用紧凑态并可覆盖展开；主要工作区和大屏改为单列，普通指标两列排列。 |
| ≤599px | 顶栏隐藏租户选择，收紧原型状态按钮与入口间距；探针筛选单列，健康摘要与阈值说明允许换行。 |
| ≤550px | 折叠侧栏隐藏，主区左侧边距归零；普通筛选与表单单列、动作换行，普通标题为 22px；长表格和字节区域保留内部滚动。 |

详情与操作弹窗采用内部滚动，正文最大高度为 75vh。操作表单、记录表单和节点检查器的字段组底部距离取 panel-inset；详情分节及底部操作区的上方距离也取 panel-inset，底部操作区分隔线上方内边距取 section-gap。详情证据摘要内边距与底部间隔为 12px；四列之间保留局部 10px 间隔，标签与值保留局部 7px 距离，在较窄视口变为两列、单列。

采集器继承相同的页面、面板与字段变量。配置摘要采用 12px 16px 内边距和 12px 字段间隔；内容分节采用 0 16px 16px 内边距，899px 及以下横向与底部取 12px。关联动作之间为 8px，独立分节之间为 12px。采集器表单正文保持内部滚动，最大高度为 65vh，599px 及以下为 62vh 并转为单列；正文内边距为 2px 3px 12px，字段组底部距离取 panel-inset，底部操作区上下内边距为 12px。

大屏嵌入布局的外沿取 panel-inset，指标栏上下内边距也取 panel-inset；标题、指标、图表区块保持 12px 间隔，宽屏不放大这些距离。全屏大屏的外沿仍为局部 30px，不推广为控制台页面外沿。认证入口保持独立介绍区和卡片布局，仅表单字段组底部距离取 panel-inset。

页面原型图库使用独立 HTML 样式，页头与主区内边距为纵向 16px、横向 4%，卡片间隔为 12px、分组底部间隔为 24px，边界入口容器内边距为 16px。图库保持三列，1100px 及以下为两列，650px 及以下为单列；其 panel-inset 不继承控制台的 899px 窄屏覆盖。

窄屏规则是已实现行为。间距评审抽样视口为 1280×720、390×844、1024×768、1728×960，几何记录的页面 scrollWidth 分别与视口宽度一致；该结果与代表页面截图只确认抽样范围，不扩展为全部 115 个功能视图、图库图片或未捕获状态的完整验收结论。

顶栏“原型状态”下拉属于评审工具，不能成为正式生产导航或权限判断的视觉规范。

原生滚动条使用辅助灰滑块与中性浅灰工作区轨道，沿用浏览器提供的操作方式。探针、PCAP 与通用详情的说明字段使用响应式列数：xs、sm 为单列，md 起为双列；原本为单列的完整性内容继续单列。该配置记录已实现行为，不扩大窄屏验收范围。

## Elevation & Depth

控制台以色调层次和细边框为主。普通白色内容面板不使用独立投影；工具栏、字段组与证据区域通过分隔线保持组织关系。交互反馈和覆盖层保留其实际阴影，不把它们推广到所有内容面板。

### Shadow Vocabulary

- **主按钮反馈**：`0 2px 0 var(--primary)` 来自固定组件样式与 controlOutline；实际按钮反馈使用操作蓝，仅适用于主按钮，不应用于内容面板。
- **窄屏覆盖导航**：源码为 `5px 0 20px #29394a1c`，只在侧栏覆盖主区时出现。
- **页签选中线**：`inset 0 -2px 0 var(--primary)` 是位置标记，不是面板抬升。
- **剧本选中节点**：`0 0 0 2px var(--selection-surface)` 表达纯灰选中边界；它不表示任务已经运行或执行成功，也不作为内容面板的阴影规则。

主按钮的实心偏移是组件生成的局部反馈，不作为供内容面板继承的阴影规则。弹窗、浮层及组件内部的其余阴影由固定 Ant Design Vue 主题生成，未独立采样，不在此记录未核实的值。

**The 平面工作区 Rule.** 控制台面板依靠底色、细边框与间距区分；投影用于控件反馈与窄屏覆盖导航，不为每个内容面板制造浮起效果。

## Shapes

控件采用轻度圆角，面板和弹窗比控件略柔和；精确半径以 frontmatter 中的 control、panel、tag、nested 为准。标签以小矩形、紧凑内边距和状态圆点构成；圆点与字节选择不替代可读内容。

结构边框通常为 1px。表格面板裁切自身边缘，表格与字节内容的横向滚动保留在内部。证据摘要、代码块和嵌套内容使用控件级或局部圆角，避免层层增加装饰外壳。登录卡片的 10px 圆角只属于登录入口，不改变工作区面板标准。

## Components

### Buttons

主按钮表达可执行的主要动作，主题高度为 34px；背景、文字、圆角与内边距见 button-primary。悬停与按下背景分别采用 button-primary-hover、button-primary-active；文字保持面板白。记录链接保持透明背景、13px 字号、500 字重和零内边距，悬停出现下划线；链接与记录入口的下划线偏移为 3px。检索示例按钮为白底细边框，悬停时边框与文字转为主色；它是辅助输入入口。

按钮与链接的键盘焦点采用源码中的 2px 主色轮廓及 3px 外偏移。主色悬停与按下以主题文件显式配置为准；其余 Ant 禁用与内部焦点反馈继续由固定组件版本及主题生成，不补造没有独立采样的状态色。

主按钮实际过渡为 all、0.2s，缓动为 cubic-bezier(0.645, 0.045, 0.355, 1)。选中菜单项的 border-color、background、padding 过渡分别为 0.3s、0.3s、0.2s，缓动分别为 ease、ease、cubic-bezier(0.215, 0.61, 0.355, 1)。不存在独立的布局宽度或主区边距动画规则。

### Inputs / Fields

字段名称与控件分开，标签为 12px；帮助说明为 11px 并解释单位、业务条件与影响。普通输入、选择和数值控件沿用 App 主题的高度、圆角与正文；正常控件边界使用 control-border，选择器、默认按钮、复选框与单选框也保持这一边界。未独立采样的 Ant 悬停、禁用与内部焦点状态继续由固定主题派生。

筛选标签与控件的 4px 距离用于关联同一条件；普通表单列间隔为 12px，字段组底部距离取 panel-inset。Ant 表单内部标签、帮助与校验反馈仍由既有组件规则组织，不将筛选区的标签距离推广到全部表单内部。

正常输入与选择占位使用 text-placeholder；按源码颜色计算，白底对比度约为 5.44:1，正常控件边界与白底约为 3.29:1。这些取值核对不代替所有页面与交互状态的可访问性验收。禁用状态不复用正常占位规则。占位提示不承担唯一字段说明。输入、文本区域与可编辑内容的光标使用主色；原生文本选择使用 selection 系列配色。

未选中且可操作的开关使用辅助灰背景，悬停使用字段标签色，白色“关闭”文字保持可辨识；禁用与已选中状态继续沿用组件主题。

检索表达式编辑框是已实现的独立样式：浅灰底、细边框、左侧行号、等宽内容，文本区域内边距为 9px 12px、13px 字号、1.9 行高；行号采用辅助灰，帮助对齐且保持可读；其内部不再叠加第二层边框或焦点投影。侧车保留这一实际输入片段，不推定普通 Ant 输入框的所有派生态。

表单在本地执行必填与业务校验。置信度保存在 0–1，列表、详情与导出转换为百分比；表单明确说明单位。生命周期按对象定义，影子、审批与自动执行单独选择。

### Chips

状态标签由短文字与 6px 圆点组成，间隔 5px。标签背景、文字与圆点按语义配对，文字色和圆点色分别取用；中性、成功、警示、危险与信息状态的含义由对应业务对象决定。标签本身不暗示点击能力。

租户使用启用／停用；决策策略使用启用／待验证／停用。严重级别、处理阶段与运行模式各自使用对应名称。未知、不完整与不可观测保留原因，不通过颜色暗示确定成功。

### Cards / Containers

白色面板以细边框与轻度圆角承载内容；筛选、指标、表格、图表、证据列表分别使用自身内部间距。指标栏为白色底，用纵向分隔区分数值；风险、关注、健康数值、标签与说明同时取对应文字色。说明位于数值附近；单位和业务边界使用较低层级文字。大屏指标保持独立深色底，数字取高亮蓝青，高危与关注数字分别取大屏玫红和琥珀。配置类页面不填充缺少业务含义的默认指标组；没有适用指标时直接进入配置与记录。

**The 业务指标 Rule.** 指标必须对应当前对象与可解释的统计口径。探针指标来自同一筛选数据集与健康阈值；离线、心跳超时和执行角色不显示推定正常的采集指标。当前范围没有捕获遥测时，观测镜像流量显示“—”及原因，不能以零流量代替不可观测。态势总览与态势大屏的探针指标使用探针列表的同一设备快照和健康阈值，按各自网络域或展示范围筛选，加载与失败时不展示指标；其他业务图表仍为合成场景，不表示所有模块已实现联动统计。

表格工具栏先显示记录类别与数量，再提供适用动作。表头使用浅灰底、12px 字号、500 字重；正文为 13px，悬停行采用独立浅色背景。记录链接及等宽编号组成行身份；状态列和操作列不与名称混写。长日期与技术字段允许表格内部滚动。

### 认证入口

认证页面使用工作区浅灰背景（workspace）。白色卡片使用分隔线浅灰边框（line）、局部 10px 圆角，不使用独立投影；介绍标题取链接蓝。卡片布局、字号与操作沿用认证入口的局部结构。

### Navigation

桌面侧栏以工作任务组织 42 个导航工作区，保留分组与子菜单，菜单行高为 41px；当前条目使用 nav-selected 背景与链接蓝文字。工作区内有 114 个功能视图，加上个人设置共 115 个；107 项需求仍由相应功能视图与对象详情承载。

已访问工作区标签与当前工作区的功能页签各自承担导航层级。已访问标签为 36px 高，最多保留五个工作区及页面目录入口；当前工作区使用纯灰底、蓝色文字和底部选中线，悬停使用表头浅灰底，标签带允许内部横向滚动。功能页签位于内容区，仅在工作区存在多个视图时显示；现行分组最多七个页签，文字为 13px，纵向内边距取 related-gap（8px），页签区域与后续内容保持 12px 距离；功能与详情页签的悬停文字使用链接蓝。

顶栏呈现当前位置、租户范围与通用入口，并以单一下拉选择原型评审状态；599px 及以下隐藏租户选择，用户仍可展开导航。折叠与覆盖行为按 Layout 中的源码断点执行。

**The 工作任务连续 Rule.** 同一对象的列表、运行状态、依据与操作在所属工作区和对象详情中衔接；避免为重复数据集或同一任务的下载步骤建立平行入口。

### 详情、证据与业务状态

详情对象名称、编号、租户范围与状态首先说明当前记录；相关依据和操作继续在同一弹窗中。身份与时间属于当前对象，不能借用其它记录的确定结论。底部操作必须能通过弹窗内部滚动与键盘焦点进入可见区。只有一个详情分节时隐藏重复页签。

探针管理的列表、资源、心跳、健康与详情共用同一设备记录；“基本信息”“运行状态”“采集与版本”“运行记录”在对象详情内组织。健康阈值同时影响列表判断与详情状态，仅保存在当前原型会话，不表示向探针下发配置。

PCAP 任务详情串联任务信息、会话完整性与下载授权；真实文件、完整性和授权条件尚未满足时保持下载禁用，合成证据清单的导出与真实 PCAP 下载各自标明含义。操作记录统一从审计日志工作区进入。

通信证据同时呈现捕获范围、会话完整性、协议结构和原始字节。选中字节使用主色背景与白色文字，并保留偏移；字节表示与尝试解码各自说明来源和限制。TLS 密文不能显示为推定明文。

设备接受、配置回读与效果观察分别展示；缺少关联任务、回读或观测证据时说明未知及所需核对。留存影响同时展示当前期限、目标期限、变更依据和保全排除；业务数据默认 180 天不替代运行 TTL 的含义。

### 空状态、加载与边界

无数据说明当前没有记录的业务原因并给出下一步。无结果判断同时包含关键词、状态、健康、网络域及高级字段；存在筛选条件时提供“清除筛选”，避免将匹配失败解释为未接入或无业务记录。加载保持页面身份和查询条件；加载失败保留重试入口。权限不足说明对象或租户范围的访问边界。这些状态不能合并成同一张“没有风险”的提示。

状态容器为白色面板，默认最小高度为 340px，使用居中的图标、标题、说明和动作。图标来自既有组件或内联 SVG，不使用文本字形冒充操作图标。

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
- **Do** 让表格在自己的容器内横向滚动，窄屏表单转单列，并保留可见的操作出口。
- **Do** 通过工作区页签与对象详情衔接相关任务，共用探针记录、健康口径与任务身份。
- **Do** 只展示适用的业务指标，静态边界说明使用低强调的信息提示，警示提示表达当前风险或限制。
- **Do** 将 180 天业务留存、旁路可见性、TLS 密文与合成数据说明作为用户理解当前结果所需的边界信息。

### Don't:

- **Don't** 用空状态、加载失败或权限不足替代彼此的业务含义。
- **Don't** 用其它记录的样本、固定成功回执或推定解密结果填补当前对象的证据缺口。
- **Don't** 将影子、审批与自动执行写成生命周期，或将设备接受显示为配置已生效与效果已验证。
- **Don't** 将原型评审状态下拉、本地提交、示例回复或合成指标写成生产能力承诺。
- **Don't** 把大屏的深色工作区配色扩散到普通表格与表单页面，或为平面面板增加装饰性厚重阴影。
- **Don't** 为控制台、认证入口、辅助区域或选中项使用浅蓝背景；蓝色保留在动作、链接、图表、文字和焦点等前景语义。
- **Don't** 传承未被现行界面采用的标题前装饰标签样式，或把登录入口的局部展示尺寸扩散为通用页面标题。
- **Don't** 把侧车合成色带、未独立采样的组件派生态或局部窄屏检查当作已经确认的全局 token 或完整验收。
