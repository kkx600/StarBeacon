<script setup lang="ts">
import {computed,ref} from 'vue'
import {useRouter} from 'vue-router'
import {SearchOutlined,ArrowRightOutlined,PictureOutlined,LinkOutlined} from '@ant-design/icons-vue'
import {groups,pages,states} from '../data/catalog'
import PageHeader from '../components/PageHeader.vue'
import MetricBar from '../components/MetricBar.vue'
const router=useRouter();const keyword=ref('');const group=ref('all')
const allRequirements=[...new Set(pages.flatMap(p=>p.requirement))]
const filtered=computed(()=>pages.filter(p=>(group.value==='all'||p.group===group.value)&&`${p.title}${p.description}${p.requirement.join(',')}`.includes(keyword.value.trim())))
const columns=[{title:'页面',dataIndex:'title',key:'title',width:190},{title:'功能说明',dataIndex:'description',width:365},{title:'需求映射',dataIndex:'requirement',key:'requirement',width:215},{title:'页面状态',key:'states',width:380}]
const systemPages=[{title:'登录',url:'/auth/login'},{title:'多因素认证',url:'/auth/mfa'},{title:'找回密码',url:'/auth/reset'},{title:'会话过期',url:'/auth/expired'},{title:'无访问权限',url:'/status/403'},{title:'页面不存在',url:'/status/404'},{title:'服务异常',url:'/status/500'},{title:'租户授权不足',url:'/status/tenant'}]
</script>
<template>
  <PageHeader title="页面目录" description="浏览全页面原型，逐页检查有数据、无数据、详情、操作、加载与失败状态。"><a-button type="primary" @click="router.push('/page/overview')">进入态势总览<ArrowRightOutlined/></a-button></PageHeader>
  <MetricBar :items="[{label:'业务页面',value:String(pages.length)},{label:'功能需求',value:String(allRequirements.length)},{label:'每页状态',value:'6'},{label:'访问边界页面',value:String(systemPages.length)}]"/>
  <a-alert message="本原型是可点击的界面与业务流程演示，全部记录为合成数据。组件操作仅改变本地状态；不连接模型、设备、数据库或真实通知渠道。" type="info" show-icon class="page-notice"/>
  <section class="panel filter-panel"><div class="catalog-filters"><a-input v-model:value="keyword" placeholder="搜索页面、功能或需求编号" allow-clear><template #prefix><SearchOutlined/></template></a-input><a-select v-model:value="group" :options="[{value:'all',label:'全部模块'},...groups.map(g=>({value:g.id,label:g.title}))]"/><a-button @click="keyword='';group='all'">重置</a-button><a href="./screenshots/index.html" target="_blank" rel="noopener"><a-button><PictureOutlined/>图片目录</a-button></a></div></section>
  <section class="panel table-panel"><div class="table-toolbar"><h2>业务页面与状态</h2><span class="muted">每个状态均可通过地址直接查看</span></div><a-table :columns="columns" :data-source="filtered" row-key="id" :pagination="{pageSize:20,showSizeChanger:true,showTotal:(total:number)=>`共 ${total} 个页面`}" :scroll="{x:1180}" size="middle"><template #bodyCell="{column,record}"><template v-if="column.key==='title'"><button class="record-link" @click="router.push(`/page/${record.id}`)">{{record.title}}</button><small class="row-id">{{groups.find(g=>g.id===record.group)?.title}}</small></template><span v-else-if="column.key==='requirement'" class="requirement-code">{{record.requirement.join(' / ')||'工作域补充页面'}}</span><div v-else-if="column.key==='states'" class="catalog-state-links"><router-link v-for="state in states" :key="state.value" :to="`/page/${record.id}?state=${state.value}`">{{state.label}}</router-link></div></template></a-table></section>
  <section class="panel boundary-pages"><div class="panel-heading"><h2>登录与访问边界</h2><span class="muted">不含真实认证服务</span></div><div><router-link v-for="page in systemPages" :key="page.url" :to="page.url"><LinkOutlined/>{{page.title}}<ArrowRightOutlined/></router-link></div></section>
</template>
