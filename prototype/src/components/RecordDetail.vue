<script setup lang="ts">
import {computed,ref,watch} from 'vue'
import {message} from 'ant-design-vue'
import {CheckCircleOutlined,ClockCircleOutlined,LinkOutlined} from '@ant-design/icons-vue'
import type {BusinessRecord,PageSpec} from '../models'
import {evidenceFor,exampleRule,packetRows,hasPacketEvidence,responseFor} from '../data/fixtures'
import RuleEditor from '../../../web/packages/shared/src/components/RuleEditor.vue'
import {formatCell} from '../composables/formatRecord'
import StatusTag from './StatusTag.vue'
import PacketWorkbench from './PacketWorkbench.vue'
import StatePanel from './StatePanel.vue'
import SensorDetail from './SensorDetail.vue'
import PcapDetail from './PcapDetail.vue'
const props=defineProps<{open:boolean;page:PageSpec;record?:BusinessRecord}>()
const emit=defineEmits<{close:[];action:[]}>()
const activeTab=ref('0');const completed=ref<string[]>([]);const note=ref('');const notes=ref<string[]>([])
const tabs=computed(()=>props.page.detailTabs??['基本信息','依据与范围','处理记录'])
const evidence=computed(()=>evidenceFor(props.page,props.record))
const response=computed(()=>responseFor(props.page,props.record))
const summary=computed(()=>props.page.columns.map(c=>({label:c.title,value:formatCell(props.record?.[c.key],c)})))
const caseMode=computed(()=>['case','incident','timeline','review'].includes(props.page.family))
watch(()=>props.open,open=>{if(open){activeTab.value='0';completed.value=[];notes.value=[];note.value=''}})
function addNote(){if(note.value.trim()){notes.value.push(note.value.trim());note.value='';message.success('笔记已保存在本地示例中。')}}
</script>
<template>
  <a-modal :open="open" :title="`${page.objectLabel}详情`" :width="1080" :footer="null" destroy-on-close @cancel="emit('close')" class="record-detail-modal" :class="{'single-detail':tabs.length===1}">
    <template v-if="record">
      <div class="detail-heading"><div><div class="detail-id">{{record.id}}</div><h2>{{record.name}}</h2></div><StatusTag :value="record.status"/></div>
      <a-tabs v-model:activeKey="activeTab">
        <a-tab-pane v-for="(tab,index) in tabs" :key="String(index)" :tab="tab">
          <SensorDetail v-if="page.family==='sensor'" :record="record" :tab="tab"/>
          <PcapDetail v-else-if="page.family==='pcap'" :record="record" :tab="tab"/>
          <template v-else-if="index===0">
            <a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small"><a-descriptions-item v-for="item in summary" :key="item.label" :label="item.label"><StatusTag v-if="item.label.includes('状态')||item.label==='判定'" :value="item.value"/><span v-else>{{item.value}}</span></a-descriptions-item><a-descriptions-item label="所属租户">{{record.tenant??'当前租户'}}</a-descriptions-item><a-descriptions-item label="观测网络域">{{record.scope??record.zone??'未提供'}}</a-descriptions-item></a-descriptions>
            <div class="detail-section"><h3>{{['alert','assessment','action','incident','case'].includes(page.family)?'判断依据与边界':'配置与使用范围'}}</h3><div class="evidence-list"><div v-for="item in evidence" :key="item.title"><div><b>{{item.title}}</b><p>{{item.value}}</p></div><StatusTag v-if="item.status" :value="item.status"/></div></div></div>
            <a-alert v-if="page.notice" :message="page.notice" type="info" show-icon/>
          </template>
          <template v-else-if="tab==='通信证据'">
            <template v-if="hasPacketEvidence(record)"><div class="evidence-strip"><div><span>源 MAC</span><b class="mono">02:00:00:20:01:18</b></div><div><span>目的 MAC</span><b class="mono">02:00:00:20:01:0f</b></div><div><span>捕获时间</span><b class="mono">09:42:16.128456789</b></div><div><span>入站／出站时间</span><b>不可观测</b></div></div><PacketWorkbench :packets="packetRows" compact/></template><StatePanel v-else state="empty" title="未提供关联原生会话" description="此条合成告警尚无对应 PCAP 样例。当前元数据可查看，但不能用无关会话作为证据。" action="查看告警信息" @action="activeTab='0'"/>
          </template>
          <template v-else-if="tab==='规则正文'"><h3>Suricata 规则</h3><RuleEditor :model-value="exampleRule" readonly/><a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small"><a-descriptions-item label="SID">1000001</a-descriptions-item><a-descriptions-item label="修订">1</a-descriptions-item><a-descriptions-item label="目标引擎">Suricata 8.0.7</a-descriptions-item><a-descriptions-item label="变量">HOME_NET / EXTERNAL_NET</a-descriptions-item></a-descriptions></template>
          <template v-else-if="tab==='报告正文'"><article class="report-document"><h2>{{record.name}}</h2><p class="muted">{{record.type}} · 合成示例 · 统计窗口：{{record.window}} · 数据快照：{{record.snapshot}}</p><h3>风险与运营概况</h3><p>本窗口内合成示例包含 1,248 条原始检测，38 条等待研判、9 个关联事件。12 条高危及严重告警集中在管理入口访问、身份尝试与异常外连。</p><h3>重点事件</h3><ol><li>管理入口访问：观察到异常请求；当前证据尚不能确认利用成功。<a href="/page/alerts">查看告警依据</a></li><li>异常外连：域名特征命中，需要结合终端与业务访问核对。</li><li>响应执行：18 个活动租约，1 个动作结果未知，应优先回读设备配置。</li></ol><h3>建议行动</h3><p>完成待研判队列核对，检查降级探针的丢包来源，复核自动策略校准资格。文件沙箱报告后到时重新评估相关事件。</p><a-alert message="总结内容需要人工审核。无终端或应用证据时，不输出“未失陷”或“已阻断”的确定结论。" type="info" show-icon/></article></template>
          <template v-else-if="caseMode&&(tab.includes('任务')||tab.includes('时间线'))">
            <div class="case-workspace"><section><h3>调查任务</h3><div v-for="task in ['核对原始告警与会话','收集终端执行证据','确认处置范围和 TTL','回读配置并观察效果']" :key="task" class="case-task"><a-checkbox :checked="completed.includes(task)" @change="({target}:{target:{checked:boolean}})=>target.checked?completed.push(task):completed.splice(completed.indexOf(task),1)">{{task}}</a-checkbox><a-tag>{{completed.includes(task)?'已完成':'待处理'}}</a-tag></div><h3>调查笔记</h3><a-textarea v-model:value="note" :rows="3" placeholder="记录观察到的事实、来源及尚未确认的内容"/><a-button type="primary" size="small" style="margin-top:8px" @click="addNote">保存笔记</a-button><p v-for="(item,i) in notes" :key="i" class="saved-note">{{item}}</p></section><section><h3>调查时间线</h3><a-timeline><a-timeline-item>09:42:16 原始网络检测命中</a-timeline-item><a-timeline-item>09:42:17 会话证据索引已接收</a-timeline-item><a-timeline-item>09:44:00 分析员接单</a-timeline-item><a-timeline-item color="orange">09:45:00 等待终端证据</a-timeline-item></a-timeline></section></div>
          </template>
          <template v-else-if="['执行链路','回执与核验','研判与响应'].includes(tab)"><a-steps :current="response.step" size="small" :items="[{title:'平台任务'},{title:'执行采集器'},{title:'设备接受'},{title:'配置读回'},{title:'效果观察'}]"/><div class="detail-section"><div class="evidence-list"><div v-for="fact in response.facts" :key="fact.title"><div><b>{{fact.title}}</b><p>{{fact.value}}</p></div><StatusTag :value="fact.status"/></div></div></div><a-alert message="接受、配置存在、效果观察是独立事实。结果未知的写操作需要先回读核对，不能无条件重试。" type="warning" show-icon/></template>
          <template v-else-if="tab==='处理记录'"><a-timeline><a-timeline-item><b>09:42:16</b> 合成示例记录创建<small class="timeline-note">来源：授权示例数据源</small></a-timeline-item><a-timeline-item><b>09:44:00</b> 陈宁查看记录<small class="timeline-note">对象范围：{{record.scope??record.zone??'未提供'}}</small></a-timeline-item><a-timeline-item color="orange"><b>09:45:00</b> 结论等待核对<small class="timeline-note">未执行外部副作用</small></a-timeline-item></a-timeline></template>
          <template v-else><div class="evidence-list"><div v-for="item in evidence" :key="item.title"><div><b>{{item.title}}</b><p>{{item.value}}</p></div><StatusTag v-if="item.status" :value="item.status"/></div></div><a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small" style="margin-top:20px"><a-descriptions-item label="版本快照">demo-20260930</a-descriptions-item><a-descriptions-item label="访问范围">当前租户授权</a-descriptions-item><a-descriptions-item label="来源引用"><LinkOutlined/> {{record.snapshot??'未提供'}}</a-descriptions-item><a-descriptions-item label="保留期限">180 天／保全对象排除清理</a-descriptions-item></a-descriptions></template>
        </a-tab-pane>
      </a-tabs>
      <div class="detail-footer"><span class="muted">合成示例 · 证据与执行状态分别核对</span><a-space><a-button @click="emit('close')">关闭</a-button><a-button v-if="!page.readOnly" type="primary" @click="emit('action')">{{page.rowAction}}</a-button></a-space></div>
    </template>
  </a-modal>
</template>
