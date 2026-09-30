---
name: "星烽 StarBeacon"
description: "以记录、证据与受控操作为中心的安全运营控制台设计系统。"
colors:
  primary: "#2563eb"
  primary-hover: "#1d4ed8"
  primary-active: "#1e40af"
  selection-surface: "#dbeafe"
  selection-text: "#1e3a8a"
  surface: "#ffffff"
  workspace: "#f5f7fa"
  line: "#e5eaf1"
  control-border: "#8794a8"
  text: "#1f2937"
  muted: "#596579"
  text-placeholder: "#5f6b7e"
  field-label: "#425169"
  record-text: "#334155"
  table-header: "#f8fafc"
  row-hover: "#f8fbff"
  nav-selected: "#eff5ff"
  tab-selected: "#f0f5ff"
  success: "#15803d"
  warning: "#a04e08"
  control-warning: "#b45309"
  danger: "#b91c1c"
  status-surface: "#f1f4f8"
  status-text: "#536072"
  status-success-surface: "#eff8f2"
  status-success-text: "#126b31"
  status-warning-surface: "#fff7e9"
  status-warning-text: "#955006"
  status-danger-surface: "#fff0ef"
  status-danger-text: "#a92222"
  status-info-surface: "#edf3ff"
  status-info-text: "#245cc6"
  screen-workspace: "#142239"
  screen-panel: "#1a2b44"
  screen-metric: "#1b2c45"
  screen-line: "#30445f"
  screen-text: "#e2ebf8"
  screen-muted: "#b8cae2"
  screen-number: "#f1f6ff"
  screen-link: "#91baff"
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
  micro: "4px"
  action-gap: "8px"
  compact-gap: "10px"
  field-gap: "12px"
  panel-inset: "16px"
  section-gap: "18px"
  form-column-gap: "20px"
  workspace-inset: "22px"
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
    textColor: "{colors.primary}"
    typography: "{typography.record-link}"
    padding: "0px"
  query-example:
    backgroundColor: "{colors.surface}"
    textColor: "#53627a"
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
    textColor: "{colors.primary}"
  status-tag:
    backgroundColor: "{colors.status-surface}"
    textColor: "{colors.status-text}"
    typography: "{typography.status-label}"
    rounded: "{rounded.tag}"
    padding: "3px 7px"
  status-tag-warning:
    backgroundColor: "{colors.status-warning-surface}"
    textColor: "{colors.status-warning-text}"
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
    padding: "14px"
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

星烽 StarBeacon 采用用户指定的 Soybean Admin Ant 后台布局，以白色侧栏、白色内容面板、浅灰工作区和克制蓝色动作形成稳定的安全运营环境。表格、表单、详情与操作弹窗承载主要工作；视觉层级服务于识别对象、核对依据和执行获准动作。

工作区保持足够的信息密度，以文字、对齐、细边框与留白区分内容。记录名称可进入详情，严重级别与执行状态同时提供可读文字和颜色。态势大屏使用独立深色工作区；这套局部配色不改变控制台的浅色基准。

本系统从已交付的 Vue 3、TypeScript 与 Ant Design Vue 原型提取；原型全部使用合成数据，操作仅改变本地内存。设计说明不代表后端、身份、模型、MCP、设备访问、数据清理或性能已经验收。

**主要特征：**

- 白色结构面板与浅灰工作区，蓝色集中表达可执行动作与可进入记录。
- 桌面优先，表格、表单、详情和操作弹窗使用一致的空间与状态语言。
- 系统中文字体、等宽技术字段和等宽数字分别承担阅读、取证与数值比较。
- 证据不足、不可观测、运行模式与生命周期各自保持独立含义。

取值依据为 [App 主题](prototype/src/App.vue)、[实际样式](prototype/src/styles.css)及实际页面；工作区与组件的局部规则按源码保留。浏览器只读采样确认了主按钮、已选导航的默认颜色、阴影与运动值。除 App 显式设置的主色悬停与按下取值外，未独立采样的 Ant Design Vue 派生态继续由固定组件版本的主题生成；本文件不补造这些值。

设计依据为用户指定布局、产品约束、实际代码和截图；未提供已批准概念图与完整质量卡。本次保留未加工的代表截图：1280px 桌面、1024px 平板、390px 移动端、1280px 通知浮层与 390px 详情。文字对比度核对与代表视口检查只支持实际覆盖范围，不等于所有功能视图的移动端或可访问性验收。截图只支持各自捕获时的源码与状态；后续重捕与结束评分不预先记为通过。历史种子仅是契约记录，不能独立证明随机候选顺序或选取结果；视觉依据保持为用户指定布局与当前代码。侧车的八阶色带是供设计面板查看的 OKLCH 派生预览，不属于现行界面 token。

## Colors

浅色工作区以中性层次支撑长时间阅读，蓝色用于操作与定位，状态色保留各自的业务含义。精确值以 frontmatter 为准；这里只说明用途。

### Primary

- **操作蓝**（primary）：主按钮、记录链接、焦点轮廓与选中字节。导航与页签使用各自的浅蓝底色，避免把选中背景当作主要动作色。
- **主色悬停**（primary-hover）、**主色按下**（primary-active）：App 主题明确指定的动作反馈，不采用未经核实的派生色值。
- **选中导航底**（nav-selected）、**选中页签底**（tab-selected）：分别标识侧栏位置与当前工作页面。
- **文本选择底**（selection-surface）、**文本选择字色**（selection-text）：原生文本选择时成对使用，保持被选中文字可读。

### Neutral

- **面板白**（surface）：侧栏、顶栏、表格、表单与详情容器。
- **工作区灰**（workspace）：控制台背景；面板通过底色与边框形成层次。
- **分隔线灰**（line）：面板边框、工具栏、字段组与记录区域的结构分隔。
- **控件边界灰**（control-border）：正常输入、选择、默认按钮、复选与单选控件的可辨识边界；结构分隔仍使用分隔线灰。
- **正文墨色**（text）、**记录文字**（record-text）：正文及密集记录；**辅助灰**（muted）用于业务说明、提示与元数据。
- **字段标签**（field-label）：筛选条件及表头；**占位灰**（text-placeholder）只说明输入预期，不替代字段名称。
- **表头浅灰**（table-header）、**记录悬停底**（row-hover）：帮助扫描和追踪当前行；静态业务边界提示沿用表头浅灰，以辅助文字与中性图标说明范围。

### 状态语义

- **成功绿**（success）用于确定的成功或健康状态；**危险红**（danger）用于严重风险与明确失败。
- **提示棕**（warning）用于源码中的警示文字；**控件警示色**（control-warning）是 Ant 主题与警示圆点的独立取值。两者承担不同的现行用途。
- 标签使用 status 系列的文字与底色配对：中性、成功、警示、危险、信息。正文语义色不直接替代小标签的文字色。
- 未知、不完整与不可观测必须写出原因。只有满足对应业务状态的记录才能呈现成功含义。

**文字与颜色规则。** 颜色辅助定位状态；严重级别、生命周期、执行结果与证据缺口必须同时有可读文字。

**语义提示规则。** 静态业务边界使用中性提示；警示色表达当前风险、异常状态或会影响操作的限制，不将所有页面说明标为警示。

### 独立深色工作区

态势大屏使用 screen 系列：深蓝工作区、相近的深色面板与指标背景、较亮的分隔线、浅色文字与浅蓝入口。数据、说明和状态仍遵循相同的证据规则；深色背景不是实时性或完整性的保证。

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

**正文与取证规则。** 业务文字使用声明的系统字体栈；原始查询、协议字节和技术标识使用等宽字体，连续数值使用等宽数字。

## Layout

控制台采用固定侧栏与流动内容区。侧栏展开宽度为 220px，折叠为 64px；顶栏高 56px，已访问工作区标签带高 44px。侧栏保持独立纵向滚动；顶栏与已访问标签带分别黏贴在工作区顶部，内容区最大宽度为 1920px。

内容区默认内边距为 22px 22px 26px。页面以工作区功能页签（存在多个视图时）、标题及业务说明、适用业务指标、业务边界提示、筛选、工具栏、表格与分页构成阅读顺序。主动作在页面或表格工具区域对齐，次级动作保留较低权重。

现行间距混用紧凑间隔与容器边距，并非严格的 8px 倍数网格。筛选面板内边距为 19px 20px；主要区块间隔为 18px；表格工具栏内边距为 16px 19px。表格单元格主题内边距为纵向 12px、横向 14px。普通表单采用两列，列间隔 20px；全宽字段跨两列。面板本身不规定统一内边距，内容类型决定其内部密度。

普通筛选区使用三个字段列加动作列；高级筛选使用四列。概览双栏默认比例为 1.65:1；协议树与载荷工作区默认双栏，字节区域保持自身横向滚动。独立大屏默认三列图表。

| 视口规则 | 已实现的布局行为 |
| --- | --- |
| ≥1650px | 内容边距变为 26px 28px，普通指标放大为 29px；大屏间隔与图表高度相应调整。 |
| ≤1199px | 探针筛选转为两列，动作独占一行。 |
| ≤1180px | 普通筛选动作独占一行，字段间隔缩小；协议与载荷改为上下区域；大屏变为两列。 |
| ≤899px | 内容边距为 18px 15px；侧栏使用紧凑态并可覆盖展开；主要工作区和大屏改为单列，普通指标两列排列。 |
| ≤599px | 顶栏隐藏租户选择，收紧原型状态按钮与入口间距；探针筛选单列，健康摘要与阈值说明允许换行。 |
| ≤550px | 折叠侧栏隐藏，主区左侧边距归零；普通筛选与表单单列、动作换行，普通标题为 22px；长表格和字节区域保留内部滚动。 |

详情与操作弹窗采用内部滚动，正文最大高度为 75vh。详情证据摘要由四列在较窄视口变为两列、单列。窄屏规则是已实现行为。代表性移动页面在 390px 视口下的页面 scrollWidth 为 390px；该结果与移动详情、1024px 代表页面的截图只确认抽样范围，不扩展为全部 115 个功能视图的移动验收结论。

顶栏“原型状态”下拉属于评审工具，不能成为正式生产导航或权限判断的视觉规范。

原生滚动条使用辅助灰滑块与工作区灰轨道，沿用浏览器提供的操作方式。探针、PCAP 与通用详情的说明字段使用响应式列数：xs、sm 为单列，md 起为双列；原本为单列的完整性内容继续单列。该配置记录已实现行为，不扩大窄屏验收范围。

## Elevation & Depth

控制台以色调层次和细边框为主。白色面板不使用独立投影；工具栏、字段组与证据区域通过分隔线保持组织关系。交互反馈和覆盖层保留其实际阴影，不把它们推广到所有内容面板。

### Shadow Vocabulary

- **主按钮反馈**：实际采样为 `0px 2px 0px 0px rgba(5, 122, 255, 0.06)`，仅适用于 Ant 主题主按钮。
- **窄屏覆盖导航**：源码为 `5px 0 20px #29394a1c`，只在侧栏覆盖主区时出现。
- **页签选中线**：`inset 0 -2px 0 var(--primary)` 是位置标记，不是面板抬升。
- **剧本选中节点**：`0 0 0 2px #e1ecff` 表达选中边界；它不表示任务已经运行或执行成功。

弹窗、浮层及组件内部的其余阴影由固定 Ant Design Vue 主题生成，未独立采样，不在此记录未核实的值。

**平面工作区规则。** 控制台面板依靠底色、细边框与间距区分；投影用于控件反馈和窄屏覆盖导航，不为每个面板制造浮起效果。

## Shapes

控件采用轻度圆角，面板和弹窗比控件略柔和；精确半径以 frontmatter 中的 control、panel、tag、nested 为准。标签以小矩形、紧凑内边距和状态圆点构成；圆点与字节选择不替代可读内容。

结构边框通常为 1px。表格面板裁切自身边缘，表格与字节内容的横向滚动保留在内部。证据摘要、代码块和嵌套内容使用控件级或局部圆角，避免层层增加装饰外壳。登录卡片的 10px 圆角只属于登录入口，不改变工作区面板标准。

## Components

### Buttons

主按钮表达可执行的主要动作，主题高度为 34px；背景、文字、圆角与内边距见 button-primary。悬停与按下背景分别采用 button-primary-hover、button-primary-active；文字保持面板白。记录链接保持透明背景、13px 字号、500 字重和零内边距，悬停出现下划线；链接与记录入口的下划线偏移为 3px。检索示例按钮为白底细边框，悬停时边框与文字转为主色；它是辅助输入入口。

按钮与链接的键盘焦点采用源码中的 2px 主色轮廓及 3px 外偏移。主色悬停与按下以 App 显式主题为准；其余 Ant 禁用与内部焦点反馈继续由固定组件版本及主题生成，不补造没有独立采样的状态色。

主按钮实际过渡为 all、0.2s，缓动为 cubic-bezier(0.645, 0.045, 0.355, 1)。选中菜单项的 border-color、background、padding 过渡分别为 0.3s、0.3s、0.2s，缓动分别为 ease、ease、cubic-bezier(0.215, 0.61, 0.355, 1)。不存在独立的布局宽度或主区边距动画规则。

### Inputs / Fields

字段名称与控件分开，标签为 12px；帮助说明为 11px 并解释单位、业务条件与影响。普通输入、选择和数值控件沿用 App 主题的高度、圆角与正文；正常控件边界使用 control-border，选择器、默认按钮、复选框与单选框也保持这一边界。未独立采样的 Ant 悬停、禁用与内部焦点状态继续由固定主题派生。

正常输入与选择占位使用 text-placeholder；按源码颜色计算，白底对比度约为 5.40:1，正常控件边界与白底约为 3.07:1。这些取值核对不代替所有页面与交互状态的可访问性验收。禁用状态不复用正常占位规则。占位提示不承担唯一字段说明。输入、文本区域与可编辑内容的光标使用主色；原生文本选择使用 selection 系列配色。

未选中且可操作的开关使用辅助灰背景，悬停使用字段标签色，白色“关闭”文字保持可辨识；禁用与已选中状态继续沿用组件主题。

检索表达式编辑框是已实现的独立样式：浅灰底、细边框、左侧行号、等宽内容，文本区域内边距为 9px 12px、13px 字号、1.9 行高；行号采用辅助灰，帮助对齐且保持可读；其内部不再叠加第二层边框或焦点投影。侧车保留这一实际输入片段，不推定普通 Ant 输入框的所有派生态。

表单在本地执行必填与业务校验。置信度保存在 0–1，列表、详情与导出转换为百分比；表单明确说明单位。生命周期按对象定义，影子、审批与自动执行单独选择。

### Chips

状态标签由短文字与 5px 圆点组成，间隔 5px。标签背景与文字使用配套的 status 系列；中性、成功、警示、危险与信息状态的含义由对应业务对象决定。标签本身不暗示点击能力。

租户使用启用／停用；决策策略使用启用／待验证／停用。严重级别、处理阶段与运行模式各自使用对应名称。未知、不完整与不可观测保留原因，不通过颜色暗示确定成功。

### Cards / Containers

白色面板以细边框与轻度圆角承载内容；筛选、指标、表格、图表、证据列表分别使用自身内部间距。指标栏用纵向分隔区分数值，说明位于数值附近；单位和业务边界使用较低层级文字。配置类页面不填充缺少业务含义的默认指标组；没有适用指标时直接进入配置与记录。

**业务指标规则。** 指标必须对应当前对象与可解释的统计口径。探针指标来自同一筛选数据集与健康阈值；离线、心跳超时和执行角色不显示推定正常的采集指标。当前范围没有捕获遥测时，观测镜像流量显示“—”及原因，不能以零流量代替不可观测。态势总览与态势大屏的探针指标使用探针列表的同一设备快照和健康阈值，按各自网络域或展示范围筛选，加载与失败时不展示指标；其他业务图表仍为合成场景，不表示所有模块已实现联动统计。

表格工具栏先显示记录类别与数量，再提供适用动作。表头使用浅灰底、12px 字号、500 字重；正文为 13px，悬停行采用独立浅色背景。记录链接及等宽编号组成行身份；状态列和操作列不与名称混写。长日期与技术字段允许表格内部滚动。

### Navigation

桌面侧栏以工作任务组织 42 个导航工作区，保留分组与子菜单，菜单行高为 41px；当前条目使用 nav-selected 背景与主色文字。工作区内有 114 个功能视图，加上个人设置共 115 个；107 项需求仍由相应功能视图与对象详情承载。

已访问工作区标签与当前工作区的功能页签各自承担导航层级。已访问标签为 36px 高，最多保留五个工作区及页面目录入口；当前工作区使用浅蓝底、蓝色文字和底部选中线，悬停使用局部浅灰底，标签带允许内部横向滚动。功能页签位于内容区，仅在工作区存在多个视图时显示；现行分组最多七个页签，文字为 13px，纵向内边距为 10px；功能与详情页签的悬停文字使用主色。

顶栏呈现当前位置、租户范围与通用入口，并以单一下拉选择原型评审状态；599px 及以下隐藏租户选择，用户仍可展开导航。折叠与覆盖行为按 Layout 中的源码断点执行。

**工作任务连续规则。** 同一对象的列表、运行状态、依据与操作在所属工作区和对象详情中衔接；避免为重复数据集或同一任务的下载步骤建立平行入口。

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

### 应遵循

- 保持白色侧栏、白色面板与浅灰工作区，沿用用户指定的后台布局。
- 将蓝色用于主要动作、可进入记录和已选导航，并保留文字说明。
- 为每类对象使用对应的生命周期；运行模式、设备接受、配置回读与效果观察分别展示。
- 使来源、时间、租户范围、完整性与证据缺口绑定当前记录；缺少依据时说明尚不可确定的内容。
- 保留有数据、无数据、详情、操作、加载和失败之间的语义差异，并提供业务原因或下一步。
- 在普通输入框与选择框中保持占位提示可读，使用可辨识的正常控件边界，禁用控件保留独立语义。
- 以 0–1 保存置信度，列表、详情与导出使用百分比；表单说明单位。
- 让表格在自己的容器内横向滚动，窄屏表单转单列，并保留可见的操作出口。
- 通过工作区页签与对象详情衔接相关任务，共用探针记录、健康口径与任务身份。
- 只展示适用的业务指标，静态边界说明使用中性提示。
- 将 180 天业务留存、旁路可见性、TLS 密文与合成数据说明作为用户理解当前结果所需的边界信息。

### 应避免

- 避免用空状态、加载失败或权限不足替代彼此的业务含义。
- 避免用其它记录的样本、固定成功回执或推定解密结果填补当前对象的证据缺口。
- 避免将影子、审批与自动执行写成生命周期，或将设备接受显示为配置已生效与效果已验证。
- 避免将原型评审状态下拉、本地提交、示例回复或合成指标写成生产能力承诺。
- 避免把深色大屏配色扩散到普通表格与表单页面，或为平面面板增加装饰性厚重阴影。
- 避免传承未被现行界面采用的标题前装饰标签样式，或把登录入口的局部展示尺寸扩散为通用页面标题。
- 避免把侧车合成色带、未独立采样的组件派生态或局部窄屏检查当作已经确认的全局 token 或完整验收。
