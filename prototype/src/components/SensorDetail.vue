<script setup lang="ts">
import {computed} from 'vue'
import type {BusinessRecord} from '../models'
import {healthFor} from '../data/sensorHealth'
import {sensorThresholds} from '../composables/useSensorHealth'
import StatusTag from './StatusTag.vue'
const props=defineProps<{record:BusinessRecord;tab:string}>()
const health=computed(()=>healthFor(props.record,sensorThresholds))
const observable=computed(()=>health.value!=='不可观测')
const execution=computed(()=>props.record.role==='执行采集器')
function metric(key:string,suffix=''){return observable.value&&props.record[key]!=null?`${props.record[key]}${suffix}`:'不可观测'}
</script>
<template>
  <template v-if="tab==='基本信息'">
    <a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small">
      <a-descriptions-item label="探针 ID">{{record.id}}</a-descriptions-item><a-descriptions-item label="连接状态"><StatusTag :value="record.status"/></a-descriptions-item>
      <a-descriptions-item label="所属租户">{{record.tenant}}</a-descriptions-item><a-descriptions-item label="站点">{{record.site??'未配置'}}</a-descriptions-item>
      <a-descriptions-item label="网络域">{{record.zone??'未配置'}}</a-descriptions-item><a-descriptions-item label="角色">{{record.role??'未配置'}}</a-descriptions-item>
      <a-descriptions-item label="最近心跳">{{record.lastSeen??'尚未上报'}}</a-descriptions-item><a-descriptions-item label="证书状态">{{record.certificate??'等待注册'}}</a-descriptions-item>
    </a-descriptions>
    <div class="sensor-health-summary"><StatusTag :value="health"/><span>资源、丢包和心跳按当前健康阈值判断。查看“运行状态”了解对应指标。</span></div>
  </template>
  <template v-else-if="tab==='运行状态'">
    <div class="sensor-runtime-heading"><h3>资源与采集质量</h3><StatusTag :value="health"/></div>
    <p class="snapshot-note">遥测快照：{{record.snapshotAt??'尚未上报'}} · 最近心跳：{{record.lastSeen??'尚未上报'}}</p>
    <a-alert v-if="!observable" message="探针离线、心跳超时或尚未接入。当前指标不可观测，不能据此判断资源和流量正常。" type="warning" show-icon class="modal-notice"/>
    <a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small">
      <a-descriptions-item label="CPU 使用率">{{metric('cpu','%')}}</a-descriptions-item><a-descriptions-item label="内存使用率">{{metric('memory','%')}}</a-descriptions-item>
      <a-descriptions-item label="磁盘使用率">{{metric('disk','%')}}</a-descriptions-item><a-descriptions-item label="持久缓冲积压">{{metric('backlog',' 条')}}</a-descriptions-item>
      <a-descriptions-item label="镜像流量">{{execution?'不适用（执行角色）':metric('bps')}}</a-descriptions-item><a-descriptions-item label="丢包率">{{execution?'不适用（执行角色）':metric('drop')}}</a-descriptions-item>
      <a-descriptions-item label="包速率">{{execution?'不适用（执行角色）':metric('pps')}}</a-descriptions-item><a-descriptions-item label="新建会话速率">{{execution?'不适用（执行角色）':metric('cps')}}</a-descriptions-item>
      <a-descriptions-item label="事件输出速率">{{execution?'不适用（执行角色）':metric('eps')}}</a-descriptions-item><a-descriptions-item label="CPU / 内存 / 磁盘阈值">{{sensorThresholds.cpu}}% / {{sensorThresholds.memory}}% / {{sensorThresholds.disk}}%</a-descriptions-item>
    </a-descriptions>
    <p class="field-hint">丢包阈值 {{sensorThresholds.drop}}%；心跳超时 {{sensorThresholds.heartbeat}} 秒。当前为单次合成快照，未提供实时趋势。</p>
  </template>
  <template v-else-if="tab==='采集与版本'">
    <a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small">
      <a-descriptions-item label="捕获接口">{{record.interface??'未配置'}}</a-descriptions-item><a-descriptions-item label="部署方式">旁路镜像（示例）</a-descriptions-item>
      <a-descriptions-item label="Agent 版本">{{record.agentVersion??'尚未上报'}}</a-descriptions-item><a-descriptions-item label="引擎版本">{{record.version??'尚未上报'}}</a-descriptions-item>
      <a-descriptions-item label="目标引擎版本">{{record.targetVersion??'未配置'}}</a-descriptions-item><a-descriptions-item label="版本回执">未提供发布任务回执</a-descriptions-item><a-descriptions-item label="规则快照">{{execution?'不适用（执行角色）':record.ruleVersion??'尚未上报'}}</a-descriptions-item><a-descriptions-item label="执行范围">{{execution?record.zone:'未授权执行设备动作'}}</a-descriptions-item>
    </a-descriptions>
    <p class="field-hint">配置目标版本不表示升级成功；生产环境以探针上报版本和发布任务回执为准。</p>
    <router-link to="/page/releases"><a-button style="margin-top:16px">查看版本发布</a-button></router-link>
  </template>
  <template v-else>
    <a-timeline v-if="record.snapshotAt"><a-timeline-item><b>{{record.lastSeen}}</b> 最近一次心跳<small class="timeline-note">{{record.id}} · 合成探针遥测</small></a-timeline-item><a-timeline-item :color="observable?'blue':'orange'"><b>{{record.snapshotAt}}</b> 健康状态评估<small class="timeline-note">{{health}} · 按快照与当前阈值计算</small></a-timeline-item></a-timeline>
    <a-empty v-else description="探针尚未上报运行记录。"/>
    <p class="field-hint">当前示例未提供历史资源序列或外部任务回执。探针编辑记录应在操作日志中查询。</p>
  </template>
</template>
