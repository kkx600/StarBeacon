import {reactive} from 'vue'
import {defaultSensorThresholds} from '../data/sensorHealth'

// 原型阈值仅保存在当前会话内；生产配置需要租户授权、版本和审计。
export const sensorThresholds=reactive({...defaultSensorThresholds})
