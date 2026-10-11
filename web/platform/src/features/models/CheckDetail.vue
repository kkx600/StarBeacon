<script setup lang="ts">
import {Modal,Descriptions,DescriptionsItem} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {checkNames,resultNames,type ModelProvider} from './models'
defineProps<{record:ModelProvider|null}>()
const emit=defineEmits<{close:[]}>()
function count(value:number|undefined){return value===undefined?'未获取':new Intl.NumberFormat('zh-CN').format(value)}
</script>
<template><Modal :open="!!record" title="模型连接验证" :width="680" :footer="null" @cancel="emit('close')"><template v-if="record">
  <a-alert v-if="record.check&&record.check.provider_revision!==record.revision" type="warning" message="验证结果对应历史配置，当前配置尚未验证。" show-icon class="section-gap" />
  <Descriptions bordered :column="1" size="small"><DescriptionsItem label="提供方">{{record.name}}</DescriptionsItem><DescriptionsItem label="当前配置修订">{{record.revision}}</DescriptionsItem><DescriptionsItem label="验证状态">{{record.check?checkNames[record.check.state]??'其他处理状态':'尚未验证'}}</DescriptionsItem><template v-if="record.check"><DescriptionsItem label="验证配置修订">{{record.check.provider_revision}}</DescriptionsItem><DescriptionsItem label="处理说明">{{resultNames[record.check.result.code]??'尚未获取处理说明'}}</DescriptionsItem><DescriptionsItem label="返回模型">{{record.check.result.returned_model??'未获取'}}</DescriptionsItem><DescriptionsItem label="请求开始">{{formatTime(record.check.created_at)}}</DescriptionsItem><DescriptionsItem label="请求结束">{{formatTime(record.check.finished_at)}}</DescriptionsItem><DescriptionsItem label="请求耗时">{{record.check.result.duration_ms==null?'未获取':count(record.check.result.duration_ms)+' ms'}}</DescriptionsItem><DescriptionsItem label="HTTP 状态">{{record.check.result.http_status??'未获取'}}</DescriptionsItem><DescriptionsItem label="输入 / 输出 / 总 Token">{{count(record.check.result.usage?.input_tokens)}} / {{count(record.check.result.usage?.output_tokens)}} / {{count(record.check.result.usage?.total_tokens)}}</DescriptionsItem></template></Descriptions>
  <p class="page-description section-gap">连接验证只确认生成接口响应。验证不携带告警正文，不保存生成文本，也不代表通过安全研判评测。结果未知时，请先核对提供方调用记录再发起新的验证。</p>
</template></Modal></template>
