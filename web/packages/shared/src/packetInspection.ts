import { packetCapture, type PacketRecord } from './packetArchives';
import { instant } from './utils/instant';

export type PacketLayer = {
  name: string;
  offset: number | null;
  length: number;
  fields: { name: string; value: string }[];
};
export type PacketInspection = {
  schema: 'packet.inspect.v1';
  archive_id: string;
  manifest_sha256: string;
  raw_sha256: string;
  packet_sha256: string;
  number: number;
  total: number;
  captured_at: string;
  captured_length: number;
  original_length: number;
  truncated: boolean;
  interface: string;
  vlan_offload: boolean;
  decode_status: 'parsed' | 'partial' | 'limited';
  layers: PacketLayer[];
  packet: string;
  checksum_validation: 'not_checked';
  payload_visibility: 'not_decoded';
};
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const integer = (v: unknown, min: number, max: number): v is number =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max;
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
export const inspectionStates = { parsed: '已解析头部', partial: '部分头部无法解析', limited: '达到协议层数限制' };

export interface SegmentFlowIdentity {
  endpoint_a: string;
  endpoint_b: string;
  transport: 'tcp' | 'udp';
  vlan?: string;
  manifest_sha256: string;
  archive_raw_sha256: string;
}

export interface SegmentFlowSource {
  archiveID: string;
  flow: SegmentFlowIdentity;
  retention: 'retained' | 'policy_truncated';
  count: number;
  interface: string;
  first: string;
  last: string;
}

interface PacketInspectionScope {
  archiveID: string;
  manifestSHA256?: string;
  rawSHA256?: string;
  count: number;
  interface: string;
  first: string | null;
  last: string | null;
}

// 回执身份、捕获范围及原字节均核对后才展示；不信任响应中的同名文件或序号。
export async function verifyPacketInspection(
  value: unknown,
  record: PacketRecord,
  number: number,
): Promise<PacketInspection> {
  const capture = packetCapture(record);
  return verifyInspection(
    value,
    {
      archiveID: record.id,
      manifestSHA256: record.manifest_sha256,
      rawSHA256: record.manifest?.encoding.raw_sha256,
      interface: capture.interface,
      count: capture.packets,
      first: capture.first_packet_at,
      last: capture.last_packet_at,
    },
    number,
  );
}

export async function verifyFlowInspection(
  value: unknown,
  source: SegmentFlowSource,
  number: number,
): Promise<PacketInspection> {
  const identity = source.flow;
  if (
    !object(value) ||
    !object(value.flow) ||
    value.retention !== source.retention ||
    value.flow.endpoint_a !== identity.endpoint_a ||
    value.flow.endpoint_b !== identity.endpoint_b ||
    value.flow.transport !== identity.transport ||
    (value.flow.vlan ?? '') !== (identity.vlan ?? '') ||
    value.flow.manifest_sha256 !== identity.manifest_sha256 ||
    value.flow.archive_raw_sha256 !== identity.archive_raw_sha256
  )
    throw new Error('原包回执与所选会话分段不一致，请重新查询');
  return verifyInspection(
    value,
    {
      archiveID: source.archiveID,
      manifestSHA256: identity.manifest_sha256,
      rawSHA256: identity.archive_raw_sha256,
      count: source.count,
      interface: source.interface,
      first: source.first,
      last: source.last,
    },
    number,
  );
}

async function verifyInspection(
  value: unknown,
  scope: PacketInspectionScope,
  number: number,
): Promise<PacketInspection> {
  const invalid = () => new Error('原包回执与所选归档、序号或字节摘要不一致，请重新读取目录');
  if (!object(value)) throw invalid();
  const r = value as unknown as PacketInspection,
    stamp = typeof r.captured_at === 'string' ? instant(r.captured_at) : null;
  const first = scope.first ? instant(scope.first) : null,
    last = scope.last ? instant(scope.last) : null;
  if (
    r.schema !== 'packet.inspect.v1' ||
    r.archive_id !== scope.archiveID ||
    !digest(r.manifest_sha256) ||
    r.manifest_sha256 !== scope.manifestSHA256 ||
    !digest(r.raw_sha256) ||
    (scope.rawSHA256 && r.raw_sha256 !== scope.rawSHA256) ||
    !digest(r.packet_sha256) ||
    r.number !== number ||
    !integer(r.number, 1, 1048576) ||
    r.total !== scope.count ||
    r.interface !== scope.interface ||
    stamp === null ||
    first === null ||
    last === null ||
    stamp < first ||
    stamp > last ||
    !integer(r.captured_length, 1, 262144) ||
    !integer(r.original_length, r.captured_length, 16777216) ||
    r.truncated !== r.original_length > r.captured_length ||
    typeof r.vlan_offload !== 'boolean' ||
    !['parsed', 'partial', 'limited'].includes(r.decode_status) ||
    r.checksum_validation !== 'not_checked' ||
    r.payload_visibility !== 'not_decoded' ||
    !Array.isArray(r.layers) ||
    r.layers.length > 16
  )
    throw invalid();
  for (const l of r.layers) {
    if (
      !object(l) ||
      typeof l.name !== 'string' ||
      l.name.length < 1 ||
      l.name.length > 64 ||
      /[\x00-\x1f]/.test(l.name) ||
      !integer(l.length, 0, r.captured_length) ||
      (l.offset !== null && !integer(l.offset, 0, r.captured_length - l.length)) ||
      !Array.isArray(l.fields) ||
      l.fields.length > 24 ||
      l.fields.some(
        f =>
          !object(f) ||
          typeof f.name !== 'string' ||
          !/^[a-z0-9_.]{1,64}$/.test(f.name) ||
          typeof f.value !== 'string' ||
          f.value.length > 768 ||
          /[\x00-\x1f]/.test(f.value),
      )
    )
      throw invalid();
  }
  if (
    typeof r.packet !== 'string' ||
    r.packet.length > 349528 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(r.packet)
  )
    throw invalid();
  let bytes: Uint8Array;
  try {
    const raw = atob(r.packet);
    if (raw.length !== r.captured_length) throw invalid();
    bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
  } catch {
    throw invalid();
  }
  if (!globalThis.crypto?.subtle) throw new Error('当前浏览器不能验证原包字节摘要，请使用 HTTPS 或本机安全入口');
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
  if (Array.from(hash, b => b.toString(16).padStart(2, '0')).join('') !== r.packet_sha256) throw invalid();
  return r;
}
