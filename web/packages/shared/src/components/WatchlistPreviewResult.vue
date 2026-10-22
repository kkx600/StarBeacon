<script setup lang="ts">
import {Descriptions as ADescriptions,DescriptionsItem as ADescriptionsItem} from 'ant-design-vue'
import {watchlistReasons,type WatchlistPreviewRequest,type WatchlistPreviewResult} from '../watchlists'
const props=defineProps<{result:WatchlistPreviewResult;input?:WatchlistPreviewRequest}>()
</script>
<template>
 <section aria-label="名单范围核验结果" class="watchlist-preview-result">
  <a-alert :type="result.admissible?'success':'warning'" show-icon :message="result.admissible?'当前范围允许启用':'当前范围不能启用'" :description="result.effective?'按核验时间，名单处于有效期内且已启用。':'名单当前未生效，材料匹配不表示策略已生效。'" class="section-gap"/>
  <ul v-if="result.reasons.length" class="watchlist-reasons"><li v-for="reason in result.reasons" :key="reason">{{watchlistReasons[reason as keyof typeof watchlistReasons]??reason}}</li></ul>
  <a-descriptions bordered :column="1" size="small"><a-descriptions-item label="核验时间（UTC）"><time :datetime="result.checked_at">{{result.checked_at}}</time></a-descriptions-item><a-descriptions-item label="范围">{{result.scope_sensor_count}} 个探针、{{result.value_count}} 项匹配值</a-descriptions-item><a-descriptions-item label="定义 SHA-256"><span class="technical watchlist-digest">{{result.definition_sha256}}</span></a-descriptions-item></a-descriptions>
  <template v-if="input&&result.matches.length"><h3 class="watchlist-result-title">提交材料的匹配结果</h3><ul class="watchlist-match-list"><li v-for="match in result.matches" :key="match.index"><span class="technical watchlist-digest">{{input.targets[match.index]?.value}}</span><span>{{match.matched?'材料匹配':'材料未匹配'}}</span></li></ul></template>
  <p class="page-description section-gap">核验只检查指定探针、输入值和业务有效期，不扫描全部历史数据，不删除告警，也不授予设备执行权限。</p>
 </section>
</template>
<style scoped>.watchlist-digest{overflow-wrap:anywhere}.watchlist-reasons{padding-left:20px;margin:0 0 12px}.watchlist-result-title{font-size:14px;margin:12px 0 8px}.watchlist-match-list{list-style:none;padding:0;margin:0;display:grid;gap:8px}.watchlist-match-list>li{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.watchlist-match-list>li>span:last-child{flex-shrink:0}:deep(.ant-descriptions-item-content){overflow-wrap:anywhere}</style>
