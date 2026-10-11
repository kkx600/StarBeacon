import type {ComputedRef} from 'vue'
import {useTaskDetail as useDetail} from '@starbeacon/shared/useTaskDetail.ts'
import {session} from '../../session'

export function useTaskDetail(task:ComputedRef<unknown>,sensor:()=>string|undefined){
 return useDetail(task,{api:()=>session.api,principal:()=>session.current.value,sensor})
}
