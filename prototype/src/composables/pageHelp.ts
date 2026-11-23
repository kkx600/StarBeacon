import { ref } from 'vue';

// 页面上的静态说明（业务边界、合成数据声明等）不再常驻显示，统一登记到页面标题旁的“说明”里。
export interface HelpEntry {
  id: number;
  message: string;
  description?: string;
}

export const helpEntries = ref<HelpEntry[]>([]);
let seed = 0;

export function registerHelp(entry: Omit<HelpEntry, 'id'>): () => void {
  const id = ++seed;
  helpEntries.value = [...helpEntries.value, { id, ...entry }];
  return () => {
    helpEntries.value = helpEntries.value.filter(item => item.id !== id);
  };
}
