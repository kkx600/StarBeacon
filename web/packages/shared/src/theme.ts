import {theme} from 'ant-design-vue'
import type {ThemeConfig} from 'ant-design-vue/es/config-provider/context'

// 浅色取值。深色主题落地时在同一结构下再提供一组取值，变量名不带明暗含义。
// 基础色交给组件库算法派生悬停、按下等交互状态。
export const componentSeeds = {
  colorPrimary: '#2f54eb',
  colorSuccess: '#3a9e50',
  colorWarning: '#e08a00',
  colorError: '#e5484d',
  colorInfo: '#2f54eb',
} as const
export const componentColors = theme.defaultAlgorithm({...theme.defaultSeed, ...componentSeeds})

// 提示类表面不取算法派生值：信息提示是纯灰表面，成功、警示、危险与业务标签共用同一组浅底。
export const componentSurfaces = {
  colorInfoBg: '#fafafa',
  colorInfoBorder: '#e5e5e5',
  colorSuccessBg: '#ecf8ee',
  colorSuccessBorder: '#b9dfc2',
  colorWarningBg: '#fff4dc',
  colorWarningBorder: '#f5d48a',
  colorErrorBg: '#fdeceb',
  colorErrorBorder: '#f5c2c0',
} as const

// 业务语义文字显式指定，保证在白底和对应浅底上的对比度不低于 4.5:1。
export const palette = {
  primary: componentColors.colorPrimary,
  primaryHover: componentColors.colorPrimaryHover,
  primaryActive: componentColors.colorPrimaryActive,
  action: componentColors.colorPrimary,
  actionHover: componentColors.colorPrimaryHover,
  actionActive: componentColors.colorPrimaryActive,
  link: componentColors.colorPrimary,
  surface: '#ffffff',
  workspace: '#f4f4f4',
  line: '#e5e5e5',
  controlBorder: '#d9d9d9',
  controlHover: componentColors.colorPrimaryHover,
  controlDisabled: '#f5f5f5',
  textDisabled: '#bfbfbf',
  scrollbar: '#e0e3e9',
  text: '#29343d',
  muted: '#6b6b6b',
  textPlaceholder: '#8c8c8c',
  fieldLabel: '#6b6b6b',
  recordText: '#29343d',
  tableHeader: '#fafafa',
  rowHover: '#fafafa',
  navSelected: '#f0f0f0',
  tabSelected: '#f3f3f3',
  selectionSurface: componentColors.colorPrimaryBg,
  selectionText: componentColors.colorPrimaryTextActive,
  success: '#2a7e3b',
  successDot: componentColors.colorSuccess,
  warning: '#9a5b00',
  warningDot: componentColors.colorWarning,
  danger: '#c4262e',
  dangerDot: componentColors.colorError,
  // “严重”用实底，与“高危”的浅底标签区分。
  critical: '#b42318',
  criticalText: '#ffffff',
  statusSurface: '#f2f2f2',
  statusText: '#595959',
  successSurface: componentSurfaces.colorSuccessBg,
  warningSurface: componentSurfaces.colorWarningBg,
  dangerSurface: componentSurfaces.colorErrorBg,
  infoSurface: componentSurfaces.colorInfoBg,
  infoText: '#29343d',
  infoDot: componentColors.colorInfo,
  // “进行中”一类状态的标签：主色文字配极浅的主色底。
  progressSurface: '#eef2ff',
  progressText: componentColors.colorPrimary,
  warningBorder: componentSurfaces.colorWarningBorder,
  teal: '#0095ad',
  violet: '#8950e9',
  chartOrange: '#d97900',
  chartNeutral: '#8c8c8c',
  chartGrid: '#ededed',
  screenWorkspace: '#181818',
  screenPanel: '#222222',
  screenMetric: '#262626',
  screenLine: '#404040',
  screenText: '#ecf6ff',
  screenMuted: '#bddefa',
  screenNumber: '#8ce6ff',
  screenLink: '#70d0ff',
  screenBlue: '#4cbcff',
  screenTeal: '#3ee0ba',
  screenViolet: '#b298ff',
  screenAmber: '#ffd174',
  screenDanger: '#ffa0b2',
  syntaxVariable: '#7434bb',
  syntaxOption: '#8a4700',
  syntaxNumber: '#b42340',
  syntaxKeyword: componentColors.colorPrimaryTextActive,
  syntaxString: '#087a43',
} as const

export const chartPalette = [palette.primary, palette.teal, palette.violet, palette.chartOrange, palette.chartNeutral]
export const screenChartPalette = [palette.screenBlue, palette.screenTeal, palette.screenViolet, palette.screenAmber]

// 根级变量同样覆盖挂载到 body 的弹窗与通知，避免浮层脱离配色体系。
export function applyPalette() {
  for (const [key, value] of Object.entries(palette)) {
    document.documentElement.style.setProperty('--' + key.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase()), value)
  }
}

// 组件取值遵循项目固定的 Ant Design Vue 4.2.6 Token 接口。
export const appTheme = {
  algorithm: theme.defaultAlgorithm,
  token: {
    ...componentSeeds,
    ...componentSurfaces,
    // 库默认链接跟随信息色；记录入口与链接按钮统一使用主色。
    colorLink: palette.link,
    colorLinkHover: palette.primaryHover,
    colorLinkActive: palette.primaryActive,
    colorText: palette.text,
    colorTextSecondary: palette.muted,
    colorTextPlaceholder: palette.textPlaceholder,
    colorTextDisabled: palette.textDisabled,
    colorBorder: palette.controlBorder,
    colorBorderSecondary: palette.line,
    colorBgContainer: palette.surface,
    colorBgLayout: palette.workspace,
    colorBgContainerDisabled: palette.controlDisabled,
    colorFillAlter: palette.tableHeader,
    colorTextHeading: palette.text,
    borderRadius: 8,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
    fontSize: 14,
    controlHeight: 34,
  },
  components: {
    Menu: {
      colorItemText: palette.recordText,
      colorItemTextHover: palette.link,
      colorItemTextSelected: palette.link,
      colorItemBgHover: palette.rowHover,
      colorItemBgSelected: palette.navSelected,
      colorItemBgActive: palette.tabSelected,
      colorSubItemBg: palette.surface,
    },
    Table: {colorFillAlter: palette.tableHeader, colorTextHeading: palette.fieldLabel},
    Form: {marginLG: 16, paddingXS: 6},
    Modal: {borderRadiusLG: 12},
  },
} satisfies ThemeConfig
