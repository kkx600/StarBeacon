import assert from 'node:assert/strict'
import {test} from 'node:test'
import {collectorPrototypeScreens,collectorScreens,collectorWorkspaces,collectorPreviewScreen,collectorPreviewWorkspace,collectorPreviewDestination,collectorPreviewCanonical,collectorTargetTabs} from '../src/data/collectorNavigation.ts'

test('九个规范视图与工程共用唯一元数据，并保留五个工作区',()=>{
 assert.equal(collectorPrototypeScreens.length,9);assert.equal(collectorWorkspaces.length,5)
 assert.deepEqual(collectorPrototypeScreens.map(screen=>screen.path),collectorScreens.map(screen=>'/collector'+screen.path))
 for(const screen of collectorPrototypeScreens){assert.equal(collectorPreviewScreen(screen.path,'',{})?.view,screen.view);assert.equal(collectorPreviewWorkspace(screen.page,screen),screen.workspace)}
})
test('旧五个基础入口可达，已交付能力成为默认内容',()=>{
 assert.equal(collectorPreviewScreen('/collector/overview','overview',{})?.view,'overview')
 assert.equal(collectorPreviewScreen('/collector/network','network',{})?.view,'interfaces')
 assert.equal(collectorPreviewScreen('/collector/connection','connection',{})?.view,'identity')
 assert.equal(collectorPreviewScreen('/collector/network','network',{view:'replay-samples'})?.view,'samples')
 assert.equal(collectorPreviewScreen('/collector/updates','updates',{view:'rules'}),undefined)
 assert.equal(collectorPreviewWorkspace('updates'),'rules');assert.equal(collectorPreviewWorkspace('maintenance'),'overview')
 assert.deepEqual(new Set(collectorTargetTabs.map(tab=>tab.path)),new Set(['/collector/maintenance','/collector/network','/collector/connection','/collector/updates']))
})
test('切换功能清除专属任务与旧视图，保留业务条件和定位',()=>{
 assert.deepEqual(collectorPreviewDestination('/collector/network/capture',{task:'old',view:'archives',source:'site-a',state:'data'},'#section'),{path:'/collector/network/capture',query:{source:'site-a',state:'data'},hash:'#section'})
})
test('规范路径消费旧view，未知选择只清理参数',()=>{
 assert.deepEqual(collectorPreviewCanonical({path:'/collector/network/interfaces',query:{view:'tasks',source:'pcap'},hash:'#task'}),{path:'/collector/rules/tasks',query:{source:'pcap'},hash:'#task',replace:true})
 assert.deepEqual(collectorPreviewCanonical({path:'/collector/network/capture',query:{view:['interfaces','capture'],state:'data'},hash:''}),{path:'/collector/network/capture',query:{state:'data'},hash:'',replace:true})
 assert.equal(collectorPreviewCanonical({path:'/collector/network',query:{view:'management'},hash:''}),undefined)
})
