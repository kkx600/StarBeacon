<script setup lang="ts">
import {computed} from 'vue'
import {Descriptions as ADescriptions,Tag as ATag} from 'ant-design-vue'
import {formatTime} from '../types'
import type {ProbeIdentityStatus} from '../utils/probeIdentity'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{identity:ProbeIdentityStatus;now?:number}>()
const phase=computed(()=>{if(props.identity.mode==='static')return 'static';const current=props.now??Date.now();return current>=Date.parse(props.identity.not_after)?'expired':current>=Date.parse(props.identity.renew_after)?'renewing':current<Date.parse(props.identity.not_before)?'future':'valid'})
const labels={static:'静态证书',expired:'证书已到期',renewing:'续签窗口',future:'证书尚未生效',valid:'证书有效'}
</script>
<template>
 <div class="identity-caption"><a-tag :color="phase==='valid'?'green':phase==='expired'||phase==='future'?'red':phase==='renewing'?'orange':'default'">{{labels[phase]}}</a-tag><span class="field-hint">{{identity.mode==='managed'?'证书和私钥由本机独立保管。':'当前使用显式配置的静态证书，不参与自动续签。'}}</span></div>
 <a-descriptions bordered size="small" :column="1">
  <a-descriptions-item label="探针标识"><span class="technical identity-value">{{identity.sensor_id}}</span></a-descriptions-item><a-descriptions-item label="注册身份"><span class="technical identity-value">{{identity.registration_id}}</span></a-descriptions-item>
  <template v-if="identity.mode==='managed'"><a-descriptions-item label="本机证书指纹"><span class="technical identity-value">{{identity.fingerprint_sha256}}</span></a-descriptions-item><a-descriptions-item label="生效时间">{{formatTime(identity.not_before)}}</a-descriptions-item><a-descriptions-item label="到期时间">{{formatTime(identity.not_after)}}</a-descriptions-item><a-descriptions-item label="自动续签窗口">{{formatTime(identity.renew_after)}} 起</a-descriptions-item></template>
 </a-descriptions>
 <p class="field-hint identity-note">本机证书状态不代表平台当前允许通信。注册身份、探针启用状态、平台吊销记录和网络连通性仍需分别核对；续签异常可在运行状态中查看。</p>
</template>
<style scoped>.identity-caption{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px}.identity-value{overflow-wrap:anywhere}.identity-note{margin:12px 0 0}</style>
