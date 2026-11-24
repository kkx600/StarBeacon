<script setup lang="ts">
defineProps<{ note: string }>();
</script>

<template>
  <div class="modal-footer-content">
    <span class="modal-footer-note">{{ note }}</span>
    <div class="modal-footer-actions"><slot /></div>
  </div>
</template>

<style scoped>
.modal-footer-content,
.modal-footer-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--related-gap);
}
.modal-footer-content {
  justify-content: space-between;
}
.modal-footer-note {
  flex: 1;
  min-width: min(220px, 100%);
  color: var(--muted);
  font-size: 12px;
  line-height: 1.6;
  text-align: start;
}
.modal-footer-actions {
  justify-content: flex-end;
  margin-inline-start: auto;
}
</style>
