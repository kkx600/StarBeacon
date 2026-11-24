<script setup lang="ts">
import type { HostHealth } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import SyslogSources from '@starbeacon/shared/components/SyslogSources.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
defineProps<{ health: HostHealth | null }>();
</script>
<template>
  <section class="panel">
    <div class="table-toolbar">
      <div>
        <h2>Syslog 接收</h2>
        <PageHelp title="Syslog 接收">
          <p>来源由本机私有文件登记，按证书或授权网段绑定身份。</p>
          <p>接收计数从本次启动开始。持久保存代表本地队列写入，平台索引状态可在主平台核对。</p>
        </PageHelp>
      </div>
    </div>
    <StatePanel
      :empty="!health?.syslog_sources?.length"
      description="尚未配置 Syslog 来源。请配置采集器来源文件并受控重启后核对监听状态。"
      ><SyslogSources :items="health?.syslog_sources ?? []" local
    /></StatePanel>
  </section>
</template>
