<script setup lang="ts">
import { Popover as APopover } from 'ant-design-vue';
import { watchlistHitFields, type WatchlistObserved } from '../watchlists';
import StatusTag from './StatusTag.vue';

defineProps<{ matches: readonly WatchlistObserved[] }>();
</script>

<template>
  <APopover v-if="matches[0]" trigger="click" placement="bottomLeft" title="命中字段与值">
    <template #content>
      <ul class="watchlist-matches">
        <li v-for="match in matches" :key="match.field + '/' + match.value">
          <StatusTag tone="neutral" :value="watchlistHitFields[match.field]" />
          <span class="technical">{{ match.value }}</span>
        </li>
      </ul>
    </template>
    <button type="button" class="record-link" :title="matches[0].value">
      <StatusTag tone="neutral" :value="watchlistHitFields[matches[0].field]" />
      <span class="technical"> {{ matches[0].value }}</span>
      <span v-if="matches.length > 1"> · 共 {{ matches.length }} 项</span>
    </button>
  </APopover>
</template>

<style scoped>
.watchlist-matches {
  display: grid;
  gap: var(--related-gap);
  width: min(360px, 70vw);
  max-height: 40vh;
  overflow: auto;
  list-style: none;
  margin: 0;
  padding: 0;
}
.watchlist-matches li {
  display: flex;
  align-items: start;
  gap: var(--related-gap);
}
</style>
