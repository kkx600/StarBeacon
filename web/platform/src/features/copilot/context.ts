import type { InjectionKey } from 'vue';
import type { Overview } from '../overview/overview';

export interface CopilotAlert {
  eventID: string;
  digest: string;
  title: string;
}
export const openCopilotAlert: InjectionKey<(alert: CopilotAlert) => void> = Symbol('告警上下文');
export const updateCopilotOverview: InjectionKey<(snapshot?: Overview) => void> = Symbol('态势总览上下文');
