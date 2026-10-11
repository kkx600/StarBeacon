import { computed, onScopeDispose, reactive, shallowRef } from 'vue'
import type { RulePackage, Sensor, SensorTask } from '@starbeacon/shared/types.ts'
import { session } from '../../session'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'

export function useRuleRelease() {
  const selected = shallowRef<RulePackage | null>(null)
  const sensors = shallowRef<Sensor[]>([])
  const tasks = shallowRef<SensorTask[]>([])
  const pending = shallowRef(false)
  const submitting = shallowRef(false)
  const error = shallowRef('')
  const taskID = shallowRef('')
  const form = reactive({ sensorID: undefined as string | undefined, revision: 1, validation: undefined as string | undefined, positive: undefined as string | undefined, negative: undefined as string | undefined, confirmed: false })
  let controller: AbortController | undefined, submitController: AbortController | undefined, stopped = false, key: string | undefined

  const target = computed(() => sensors.value.find(item => item.id === form.sensorID))
  const expectedSHA = computed(() => target.value?.health.registered_rules_sha256 ?? '')
  const options = computed(() => sensors.value.map(item => ({ value: item.id, label: `${item.name} · ${item.status === 'online' ? '在线' : '不可部署'}`, disabled: !item.active || item.status !== 'online' || !item.health.task_capabilities?.includes('rules.apply') || !/^[a-f0-9]{64}$/.test(item.health.registered_rules_sha256 ?? '') })))
  const facts = computed(() => {
    const value = selected.value
    if (!value) return []
    return tasks.value.filter(item => {
      const result = item.receipt.result, finished = Date.parse(item.receipt.finished_at ?? '')
      return item.sensor_id === form.sensorID && item.state === 'succeeded' && item.receipt.state === 'succeeded' && !item.receipt.code && result?.package_id === value.id && result.revision === form.revision && result.engine_version === '8.0.7' && Number.isFinite(finished) && finished >= Date.now() - 86400000 && finished <= Date.now() + 60000
    })
  })
  function evidenceOptions(kind: 'validation' | 'positive' | 'negative') {
    return facts.value.filter(item => {
      const result = item.receipt.result!
      if (kind === 'validation') return item.kind === 'rules.validate' && result.syntax === 'passed'
      return item.kind === 'rules.replay' && result.replay === 'completed' && result.rule_mode === 'package' && typeof result.alert_count === 'number' && (kind === 'positive' ? result.alert_count > 0 : result.alert_count === 0)
    }).map(item => ({ value: item.id, label: `${item.id} · ${kind === 'validation' ? '装载通过' : `${item.receipt.result!.alert_count} 次命中`}` }))
  }
  const validations = computed(() => evidenceOptions('validation'))
  const positives = computed(() => evidenceOptions('positive'))
  const negatives = computed(() => evidenceOptions('negative'))

  function resetEvidence() {
    form.validation = undefined; form.positive = undefined; form.negative = undefined; form.confirmed = false
    key = undefined; taskID.value = ''; error.value = ''
  }
  function changed() { key = undefined; taskID.value = ''; error.value = ''; form.confirmed = false }
  async function open(value: RulePackage) {
    if (stopped || submitting.value || session.current.value?.role !== 'admin') return
    controller?.abort(); controller = new AbortController(); const current = controller
    selected.value = value; sensors.value = []; tasks.value = []; form.sensorID = undefined; form.revision = value.revision; resetEvidence(); pending.value = true
    try {
      const result = await readSensorDirectory(session.api,current.signal)
      if (!current.signal.aborted) sensors.value = result
    } catch (cause) { if (!current.signal.aborted) error.value = cause instanceof Error ? cause.message : '探针信息读取失败' }
    finally { if (controller === current) pending.value = false }
  }
  async function loadEvidence() {
    if (stopped || submitting.value || !selected.value) return
    controller?.abort(); controller = new AbortController(); const current = controller
    resetEvidence(); tasks.value = []
    if (!form.sensorID) { pending.value = false; return }
    pending.value = true
    try {
      const result = await session.api.request<{ items: SensorTask[] }>(`/tasks?sensor_id=${encodeURIComponent(form.sensorID)}`, { signal: current.signal })
      if (!current.signal.aborted) tasks.value = result.items
    } catch (cause) { if (!current.signal.aborted) error.value = cause instanceof Error ? cause.message : '验证回执读取失败' }
    finally { if (controller === current) pending.value = false }
  }
  async function submit() {
    if (stopped || pending.value || submitting.value || taskID.value || session.current.value?.role !== 'admin') return
    if (!selected.value || !form.sensorID || options.value.find(item => item.value === form.sensorID)?.disabled !== false || !/^[a-f0-9]{64}$/.test(expectedSHA.value) || !Number.isSafeInteger(form.revision) || form.revision < 1 || form.revision > selected.value.revision || !validations.value.some(item => item.value === form.validation) || !positives.value.some(item => item.value === form.positive) || !negatives.value.some(item => item.value === form.negative) || !form.confirmed) {
      error.value = '请选择目标探针、修订及三份有效回执，并确认部署范围'; return
    }
    submitting.value = true; error.value = ''; key ??= crypto.randomUUID()
    submitController?.abort(); submitController = new AbortController(); const current = submitController
    try {
      const result = await session.api.request<{ id: string }>(`/sensors/${encodeURIComponent(form.sensorID)}/tasks`, {
        method: 'POST', signal: current.signal, headers: { 'Idempotency-Key': key }, body: { kind: 'rules.apply', package_id: selected.value.id, revision: form.revision, validation_task_id: form.validation, positive_replay_task_id: form.positive, negative_replay_task_id: form.negative, expected_rules_sha256: expectedSHA.value },
      })
      if (!current.signal.aborted) taskID.value = result.id
    } catch (cause) { if (!current.signal.aborted) error.value = cause instanceof Error ? cause.message : '发布任务提交失败' }
    finally { if (submitController === current) submitting.value = false }
  }
  function close() {
    if (submitting.value) return
    controller?.abort(); selected.value = null; pending.value = false; resetEvidence()
  }
  onScopeDispose(() => { stopped = true; controller?.abort(); submitController?.abort() })
  return { selected, sensors, tasks, pending, submitting, error, taskID, form, expectedSHA, options, validations, positives, negatives, open, loadEvidence, submit, close, changed }
}
