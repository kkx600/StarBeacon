import {theme} from 'ant-design-vue'
import type {ThemeConfig} from 'ant-design-vue/es/config-provider/context'

// 基础色沿用参考前端；组件交互色与提示底色由组件库同一算法生成。
export const componentSeeds = {
  colorPrimary: '#5d87ff',
  colorSuccess: '#60c041',
  colorWarning: '#f9901f',
  colorError: '#e13c39',
  colorInfo: '#38c0fc',
} as const
export const componentColors = theme.defaultAlgorithm({...theme.defaultSeed, ...componentSeeds})

// 自绘图形与业务标记复用组件派生色；控制台和态势大屏各自保持表面层次。
export const palette = {
  primary: componentColors.colorPrimary,
  primaryHover: componentColors.colorPrimaryHover,
  primaryActive: componentColors.colorPrimaryActive,
  action: componentColors.colorPrimary,
  actionHover: componentColors.colorPrimaryHover,
  actionActive: componentColors.colorPrimaryActive,
  link: componentColors.colorPrimary,
  surface: '#ffffff',
  workspace: '#f7f7f7',
  line: '#e8e8e8',
  controlBorder: '#e4e7ed',
  controlHover: componentColors.colorPrimaryHover,
  controlDisabled: '#f5f5f5',
  textDisabled: '#bfbfbf',
  scrollbar: '#e0e3e9',
  navigationShadow: '#29394a1c',
  text: '#29343d',
  muted: '#6b6b6b',
  textPlaceholder: '#a8abb2',
  fieldLabel: '#6b6b6b',
  recordText: '#29343d',
  tableHeader: '#fafafa',
  rowHover: '#fafafa',
  navSelected: '#f0f0f0',
  tabSelected: '#f3f3f3',
  selectionSurface: componentColors.colorPrimaryBg,
  selectionText: componentColors.colorPrimaryTextActive,
  success: componentColors.colorSuccessTextActive,
  successDot: componentColors.colorSuccess,
  warning: componentColors.colorWarningTextActive,
  warningDot: componentColors.colorWarning,
  danger: componentColors.colorErrorTextActive,
  dangerDot: componentColors.colorError,
  statusSurface: '#f3f3f3',
  statusText: '#6b6b6b',
  successSurface: componentColors.colorSuccessBg,
  warningSurface: componentColors.colorWarningBg,
  dangerSurface: componentColors.colorErrorBg,
  infoSurface: componentColors.colorInfoBg,
  infoText: '#29343d',
  infoDot: componentColors.colorInfo,
  warningBorder: componentColors.colorWarningBorder,
  teal: '#0095ad',
  violet: '#8950e9',
  chartOrange: '#d97900',
  chartNeutral: '#6d83a5',
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
    // 库默认链接跟随信息色；记录入口与链接按钮统一使用参考前端的主蓝。
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
