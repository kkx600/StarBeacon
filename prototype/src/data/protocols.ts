import type { ProtocolEntry,ProtocolReport } from '../../../web/packages/shared/src/protocols'
import { protocolLimitNames } from '../../../web/packages/shared/src/protocols'

// 仅为界面合成数据，不执行原生命令或授予协议效果资格。
export function protocolObservation():ProtocolReport {
  const row:ProtocolEntry={protocol:'http',name:'HTTP/1',bindings:[{transport:'tcp',mode:'yes'}],native_listed:true,recognition:'configured',transactions:'configured',online_rules:'requires_validation',file_extraction:'not_implemented',packet_forensics:'not_implemented',external_logs:'not_implemented',qualification:'not_qualified'}
  return {schema_version:1,state:'observed',observed_at:'2026-10-14T09:30:00Z',source:'managed_configuration',capture_active:true,engine_version:'8.0.7',engine_sha256:'a'.repeat(64),config_sha256:'b'.repeat(64),protocols:[
    {...row,protocol:'ethernet',name:'Ethernet',bindings:[],native_listed:false,recognition:'unknown',transactions:'unknown',packet_forensics:'packet_headers_only'},row,
    {...row,protocol:'http2',name:'HTTP/2',recognition:'native_listed',transactions:'unknown'},
    {...row,protocol:'tls',name:'TLS'},
    {...row,protocol:'quic',name:'QUIC',bindings:[{transport:'udp',mode:'unknown'}],recognition:'native_listed',transactions:'unknown'},
    {...row,protocol:'dns',name:'DNS',bindings:[{transport:'tcp',mode:'no'},{transport:'udp',mode:'yes'}],recognition:'partial',transactions:'partial'},
    {...row,protocol:'imap',name:'IMAP',bindings:[{transport:'tcp',mode:'detection-only'}],recognition:'detection_only',transactions:'disabled',online_rules:'disabled'},
    {...row,protocol:'ssh',name:'SSH',transactions:'not_configured'},
    {...row,protocol:'pgsql',name:'PostgreSQL',bindings:[{transport:'tcp',mode:'no'}],native_listed:false,recognition:'disabled',transactions:'disabled',online_rules:'disabled'},
    {...row,protocol:'modbus',name:'Modbus',bindings:[{transport:'tcp',mode:'unknown'}],native_listed:false,recognition:'unlisted',transactions:'unknown'},
  ],limits:Object.keys(protocolLimitNames).map((key,index)=>({key,value:index===3?'1mb':index===6?'':'32mb'}))}
}
