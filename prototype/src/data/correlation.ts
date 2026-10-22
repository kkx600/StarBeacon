// 合成原型与交互测试材料，不代表真实检测资格。
import type {CorrelationRule,CorrelationRequest,CorrelationResult} from '../../../web/packages/shared/src/correlation'
export const correlationRule:CorrelationRule = {
  "tenant_id": "t_office",
  "id": "correlation_example",
  "revision": 1,
  "name": "同源多目标活动",
  "description": "核对同一探针内已观察到的告警窗口",
  "active": true,
  "definition": {
    "schema_version": "correlation-rule.v1",
    "dataset": "alerts",
    "filter": "",
    "group_by": "source.ip",
    "metric": "count",
    "distinct_field": "",
    "window_seconds": 60,
    "threshold": 2
  },
  "definition_sha256": "b591bd5ff6afc36205d306aece09663d1d37d7cf290a19804516eca097e65885",
  "created_by": "u_admin",
  "created_at": "2026-10-21T11:00:00Z",
  "expires_at": "2027-04-19T12:00:00Z"
}
export const correlationQuery:CorrelationRequest = {
  "expected_revision": 1,
  "start": "2026-10-21T11:58:00Z",
  "end": "2026-10-21T12:00:00Z"
}
export const correlationResult:CorrelationResult = {
  "schema_version": "correlation-backtest.v1",
  "tenant_id": "t_office",
  "rule_id": "correlation_example",
  "rule_revision": 1,
  "definition_sha256": "b591bd5ff6afc36205d306aece09663d1d37d7cf290a19804516eca097e65885",
  "query": {
    "expected_revision": 1,
    "start": "2026-10-21T11:58:00Z",
    "end": "2026-10-21T12:00:00Z"
  },
  "observed_at": "2026-10-21T12:00:00Z",
  "snapshot_sha256": "6918e4f9a1de786795bcbc2a150de101259002a60905ed11b0f8e2a457f21fa1",
  "unique_events": 4,
  "duplicate_events": 0,
  "missing_group": 0,
  "threshold_windows": 2,
  "partial_windows": 0,
  "source_coverage": "not_attested",
  "execution_authorized": false,
  "windows": [
    {
      "detection_id": "7cd0584fac34f917e17ba29eec555804dc194e4f640c5a95acc71a08c83d2cb4",
      "sensor_id": "probe_1",
      "sensor_registration_id": "register_1",
      "group_value": "192.0.2.1",
      "start": "2026-10-21T11:58:00Z",
      "end": "2026-10-21T11:59:00Z",
      "count": 2,
      "metric_value": 2,
      "missing_metric": 0,
      "status": "threshold_observed",
      "evidence_sha256": "63d0ae4f49dd1b89d32fa63e758423510b3ff9cf2af945d79a0f71c64a965ec4",
      "evidence": [
        {
          "event_id": "correlation_event_00",
          "raw_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "timestamp": "2026-10-21T11:58:01Z"
        },
        {
          "event_id": "correlation_event_01",
          "raw_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "timestamp": "2026-10-21T11:58:02Z"
        }
      ],
      "evidence_truncated": false
    },
    {
      "detection_id": "40e1b653acacf1704f0f1f4e8eda01273d34bad6f34ae0846c581abdcdc71f04",
      "sensor_id": "probe_1",
      "sensor_registration_id": "register_1",
      "group_value": "192.0.2.1",
      "start": "2026-10-21T11:59:00Z",
      "end": "2026-10-21T12:00:00Z",
      "count": 2,
      "metric_value": 2,
      "missing_metric": 0,
      "status": "threshold_observed",
      "evidence_sha256": "d781b906fdda28288ceee1c7ee6fa633a0f185b2f6cc2082d33c44141a262266",
      "evidence": [
        {
          "event_id": "correlation_event_02",
          "raw_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "timestamp": "2026-10-21T11:59:01Z"
        },
        {
          "event_id": "correlation_event_03",
          "raw_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "timestamp": "2026-10-21T11:59:02Z"
        }
      ],
      "evidence_truncated": false
    }
  ]
}
export const correlationEmpty:CorrelationResult = {
  "schema_version": "correlation-backtest.v1",
  "tenant_id": "t_office",
  "rule_id": "correlation_example",
  "rule_revision": 1,
  "definition_sha256": "b591bd5ff6afc36205d306aece09663d1d37d7cf290a19804516eca097e65885",
  "query": {
    "expected_revision": 1,
    "start": "2026-10-21T11:58:00Z",
    "end": "2026-10-21T12:00:00Z"
  },
  "observed_at": "2026-10-21T12:00:00Z",
  "snapshot_sha256": "15fea38fdbda3421aa474979d9dd4150bc8ed97a4a75d894b45c7b6a779cebfd",
  "unique_events": 0,
  "duplicate_events": 0,
  "missing_group": 0,
  "threshold_windows": 0,
  "partial_windows": 0,
  "source_coverage": "not_attested",
  "execution_authorized": false,
  "windows": []
}
