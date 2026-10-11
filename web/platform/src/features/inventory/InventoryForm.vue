<script setup lang="ts">
import {reactive,shallowRef} from 'vue'
import {Modal as AModal,Select as ASelect,Switch as ASwitch} from 'ant-design-vue'
import {createDraft,criticalityNames,purposeNames,inventoryObjectNames,type InventoryKind,type InventoryRecord,type InventoryData} from './inventory'
import GroupSelector from './GroupSelector.vue'
const props=defineProps<{kind:InventoryKind;record:InventoryRecord|null;pending:boolean;error:string}>()
const emit=defineEmits<{save:[data:InventoryData,id:string];close:[]}>()
const form=reactive(createDraft(props.kind,props.record?.data)),id=props.record?.id??`obj_${crypto.randomUUID().replaceAll('-','')}`
const interfaceKeys=shallowRef((form.interfaces??[]).map(()=>crypto.randomUUID()))
const ipText=reactive((form.interfaces??[]).map(iface=>iface.ips.join('\n')))
const rules={name:[{required:true,message:'请输入名称',trigger:'blur'},{max:128,message:'名称不能超过 128 个字符'}],network_domain:[{required:true,message:'请输入网络域',trigger:'blur'}],prefix:[{required:true,message:'请输入 IPv4 或 IPv6 网段',trigger:'blur'}]}
function addInterface(){form.interfaces??=[];form.interfaces.push({name:'',mac:'',ips:[]});ipText.push('');interfaceKeys.value=[...interfaceKeys.value,crypto.randomUUID()]}
function removeInterface(index:number){form.interfaces?.splice(index,1);ipText.splice(index,1);interfaceKeys.value=interfaceKeys.value.filter((_key,i)=>i!==index)}
function submit(){if(props.pending)return;const data=JSON.parse(JSON.stringify(form)) as InventoryData;data.interfaces?.forEach((iface,index)=>{iface.ips=(ipText[index]??'').trim().split(/[\s,]+/).filter(Boolean)});emit('save',data,id)}
</script>
<template>
  <a-modal :title="`${record?'编辑':'创建'}${inventoryObjectNames[kind]}`" open :width="760" :footer="null" :mask-closable="!pending" :closable="!pending" :keyboard="!pending" @cancel="emit('close')">
    <a-form :model="form" :rules="rules" layout="vertical" :disabled="pending" @finish="submit">
      <a-alert v-if="error" :message="error" type="error" show-icon class="section-gap" />
      <div class="inventory-fields">
        <a-form-item label="名称" name="name"><a-input v-model:value="form.name" :maxlength="128" /></a-form-item>
        <a-form-item v-if="kind!=='networks'" label="责任人" name="owner"><a-input v-model:value="form.owner" :maxlength="128" /></a-form-item>
        <a-form-item v-if="kind!=='groups'" label="网络域" name="network_domain"><a-input v-model:value="form.network_domain" :maxlength="128" placeholder="同一地址空间的稳定名称" /></a-form-item>
        <a-form-item v-if="kind!=='groups'" label="资产组" html-for="inventory-group"><GroupSelector input-id="inventory-group" :model-value="form.group_id??''" :disabled="pending" @update:model-value="form.group_id=$event" /></a-form-item>
        <a-form-item v-if="kind==='assets'" label="重要性" html-for="inventory-criticality"><a-select id="inventory-criticality" aria-label="重要性" v-model:value="form.criticality" :options="Object.entries(criticalityNames).map(([value,label])=>({value,label}))" /></a-form-item>
        <a-form-item v-if="kind==='networks'" label="网段" name="prefix"><a-input v-model:value="form.prefix" placeholder="192.0.2.0/24 或 2001:db8::/32" /></a-form-item>
        <a-form-item v-if="kind==='networks'" label="用途" html-for="inventory-purpose"><a-select id="inventory-purpose" aria-label="用途" v-model:value="form.purpose" :options="Object.entries(purposeNames).map(([value,label])=>({value,label}))" /></a-form-item>
        <a-form-item label="使用状态" html-for="inventory-active"><a-switch id="inventory-active" aria-label="使用状态" v-model:checked="form.active" checked-children="使用中" un-checked-children="停用" /></a-form-item>
      </div>
      <section v-if="kind==='assets'" class="interface-editor">
        <div class="panel-header"><h2>网络接口</h2><a-button size="small" :disabled="pending||(form.interfaces?.length??0)>=32" @click="addInterface">添加接口</a-button></div>
        <p v-if="!form.interfaces?.length" class="page-description">尚未配置网络接口，可保存后继续完善通信地址。</p>
        <div v-for="(iface,index) in form.interfaces" :key="interfaceKeys[index]" class="interface-fields">
          <a-form-item label="接口名称" :html-for="'inventory-interface-'+interfaceKeys[index]" :name="['interfaces',index,'name']" :rules="[{required:true,message:'请输入接口名称'}]"><a-input :id="'inventory-interface-'+interfaceKeys[index]" v-model:value="iface.name" :maxlength="128" placeholder="eth0" /></a-form-item>
          <a-form-item label="MAC 地址" :html-for="'inventory-mac-'+interfaceKeys[index]"><a-input :id="'inventory-mac-'+interfaceKeys[index]" aria-label="MAC 地址" v-model:value="iface.mac" placeholder="aa:bb:cc:dd:ee:ff" /></a-form-item>
          <a-form-item label="IP 地址" :html-for="'inventory-ip-'+interfaceKeys[index]" class="interface-addresses"><a-textarea :id="'inventory-ip-'+interfaceKeys[index]" aria-label="IP 地址" v-model:value="ipText[index]" :auto-size="{minRows:2,maxRows:4}" placeholder="每行一个 IP 地址，支持 IPv4 与 IPv6" /></a-form-item>
          <a-button class="interface-remove" :disabled="pending" danger size="small" @click="removeInterface(index)">移除接口</a-button>
        </div>
      </section>
      <a-form-item label="说明" html-for="inventory-description"><a-input id="inventory-description" aria-label="说明" v-model:value="form.description" :maxlength="1024" /></a-form-item>
      <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="pending">保存</a-button><a-button :disabled="pending" @click="emit('close')">取消</a-button></div>
    </a-form>
  </a-modal>
</template>
<style scoped>
.inventory-fields,.interface-fields {display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 var(--field-gap);min-width:0}
.interface-editor {margin-bottom:var(--section-gap)}
.interface-editor .panel-header {padding:0 0 var(--section-gap)}
.interface-fields {padding:var(--section-gap);border:1px solid var(--line);border-radius:6px;margin-bottom:var(--section-gap);background:var(--surface)}
.interface-addresses {grid-column:1/-1}.interface-remove {justify-self:start;grid-column:1/-1}
@media(max-width:700px){.inventory-fields,.interface-fields {grid-template-columns:minmax(0,1fr)}}
</style>
