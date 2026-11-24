import { shallowRef, type Ref } from 'vue';
import { defaultPageSize } from '../pagination';

export function useCursorPageSize(cursors: Ref<string[]>, pending: Readonly<Ref<boolean>>, reload: () => void) {
  const pageSize = shallowRef(defaultPageSize);
  function changePageSize(size: number) {
    if (pending.value || size === pageSize.value) return;
    pageSize.value = size;
    cursors.value = [''];
    reload();
  }
  return { pageSize, changePageSize };
}
