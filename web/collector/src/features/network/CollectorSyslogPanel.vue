<script setup lang="ts">
import type {HostHealth} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import SyslogSources from '@starbeacon/shared/components/SyslogSources.vue'
defineProps<{health: HostHealth|null}>()
</script>
<template><section class="panel"><div class="panel-header"><h2>Syslog 接收</h2></div><div class="panel-body"><a-alert type="info" show-icon message="来源由本机私有文件登记，按证书或授权网段绑定身份。计数仅涵盖本次运行，持久保存仅证明本地队列写入。"/></div><StatePanel :empty="!health?.syslog_sources?.length" description="尚未配置 Syslog 来源。请配置采集器来源文件并受控重启后核对监听状态。"><SyslogSources :items="health?.syslog_sources??[]" local/></StatePanel></section></template>
