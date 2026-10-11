<script setup lang="ts">
import { computed } from 'vue'
import { Descriptions as ADescriptions,Table as ATable } from 'ant-design-vue'
import {sampleOrigin} from '../utils/sample'
import {formatBytes} from '../utils/format'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{result:Record<string,unknown>;local?:boolean}>()
const completed=computed(()=>props.result.replay==='completed')
const metadata=computed(()=>props.result.sample_metadata as Record<string,unknown>|undefined)
const origin=computed(()=>sampleOrigin(props.result.sample_origin))
interface HandshakeObservation {assessed_flows:number;complete_handshakes:number;incomplete_flows:number;reused_tuples:number;skipped_packets:number;limited:boolean;limit_reasons:string[];checksum_validation:string}
const handshake=computed(()=>metadata.value?.tcp_handshake as HandshakeObservation|undefined)
const handshakeLimits:Record<string,string>={ip_fragmentation:'分片帧未重组',decode_error:'存在解析失败帧',truncated_or_invalid_packet:'存在截断或无效帧',unsupported_network_layer:'部分网络封装未评估',vlan_depth:'VLAN 层级超出上限',flow_limit:'超过 32,768 个流的评估上限',tuple_reuse_or_simultaneous_open:'存在五元组复用或同时打开'}
const alerts=computed(()=>Array.isArray(props.result.alerts)?props.result.alerts.map((row,index)=>({...row,key:index})):[])
const packetTime=(value:unknown)=>typeof value==='string'?new Date(value).toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false,fractionalSecondDigits:3}):'未获取'
const columns=[{title:'SID / 修订',key:'rule',width:120},{title:'规则名称',dataIndex:'signature',width:230},{title:'源 → 目的',key:'address',width:280},{title:'数据包序号',dataIndex:'pcap_cnt',width:130},{title:'捕获时间',key:'time',width:190}]
</script>
<template>
  <a-alert :type="completed?'info':'error'" show-icon :message="completed?(result.match_status==='matched'?'重放完成，检测到规则命中':'重放完成，未检测到规则命中'):'重放未完成，请核对失败原因与引擎日志'" class="section-gap"><template #description>离线重放不向真实网络发包；检测结论受样本完整性和检测配置影响。</template></a-alert>
  <a-alert v-if="result.reason" type="error" show-icon :message="String(result.reason)" class="section-gap" />
  <a-alert v-if="origin" type="info" show-icon message="HTTP Raw 合成样本" description="三次握手、地址及包时间由离线封装生成。请求字节保持原样，无合成 HTTP 响应；结果不能证明真实网络通信或攻击成功。" class="section-gap" />
  <a-descriptions bordered :column="1" size="small" class="section-gap">
    <a-descriptions-item label="包数 / 命中 / 耗时">{{ result.packets_processed??'未确认' }} / {{ result.alert_count??'未确认' }} / {{ result.duration_ms??'未确认' }} ms</a-descriptions-item>
    <a-descriptions-item label="样本摘要"><span class="technical">{{ result.sample_sha256??'未确认' }}</span></a-descriptions-item>
    <a-descriptions-item v-if="origin" label="HTTP Raw 来源">{{ formatBytes(origin.raw_bytes) }} · {{ origin.encoder }}<br /><span class="technical">{{ origin.raw_sha256 }}</span></a-descriptions-item>
    <a-descriptions-item label="规则来源">{{ result.rule_mode==='registered'?'登记规则快照':local?'本次输入规则':'指定规则包' }} <span v-if="result.revision&&!local">· 修订 {{ result.revision }}</span></a-descriptions-item>
    <a-descriptions-item label="规则摘要"><span class="technical">{{ result.rules_sha256??'未确认' }}</span></a-descriptions-item>
    <a-descriptions-item label="引擎 / 检测配置">Suricata {{ result.engine_version??'未确认' }} · 离线限制配置 · 重组深度 1 MiB · 校验和检查</a-descriptions-item>

    <a-descriptions-item v-if="metadata" label="首包 / 末包时间">{{ packetTime(metadata.first_packet_at) }} / {{ packetTime(metadata.last_packet_at) }}</a-descriptions-item>
    <a-descriptions-item v-if="metadata" label="样本完整性">截断包 {{ metadata.truncated_packets }}<span v-if="!handshake"> · TCP 握手尚未评估</span></a-descriptions-item>
    <a-descriptions-item v-if="handshake" :label="origin?'合成 TCP 握手观测':'TCP 握手观测'"><template v-if="handshake.assessed_flows">已观察 {{ handshake.complete_handshakes }} 组完整三次握手 · {{ handshake.incomplete_flows }} 个流缺少完整握手 · 评估 {{ handshake.assessed_flows }} 个流</template><template v-else>未观察到可评估的 TCP 流</template><p class="page-description">依据 SYN、SYN-ACK、ACK 方向及序号核对；不证明载荷完整或攻击成功。样本观测未校验 TCP 校验和，引擎重放独立执行校验和检查。</p><p v-if="handshake.limited" class="page-description">观测限制：{{ handshake.limit_reasons.map(reason=>handshakeLimits[reason]??'其他观测限制').join('；') }}。跳过 {{ handshake.skipped_packets }} 帧，五元组复用 {{ handshake.reused_tuples }} 处。</p></a-descriptions-item>
    <a-descriptions-item v-if="metadata" label="链路层 / MAC">{{ metadata.link_type }} · {{ Array.isArray(metadata.mac_addresses)?metadata.mac_addresses.join('，'):'未获取' }}<p v-if="metadata.mac_addresses_limited" class="page-description">地址数量超过展示上限，仅列出前 32 个 MAC 地址。</p></a-descriptions-item>
  </a-descriptions>
  <p class="page-description section-gap">未命中不能证明流量安全；TLS 密文、截断、缺少握手、校验和与重组深度均可能影响检测结果。重放结果不自动授予规则发布资格。</p>
  <h2>命中明细</h2><p class="page-description section-gap">最多展示前 30 条命中，命中总数及最多 200 条规则汇总保存在执行回执中。</p>
  <div class="table-wrap"><a-table :columns="columns" :data-source="alerts" size="small" :pagination="{pageSize:5,hideOnSinglePage:true,showSizeChanger:false}" :scroll="{x:960}"><template #bodyCell="{column,record}"><template v-if="column.key==='rule'">{{ record.signature_id }} / {{ record.rev }}</template><span v-else-if="column.key==='address'" class="technical">{{ record.src_ip }}:{{ record.src_port }} → {{ record.dest_ip }}:{{ record.dest_port }}</span><template v-else-if="column.key==='time'">{{ packetTime(record.timestamp) }}</template></template></a-table></div>
</template>
