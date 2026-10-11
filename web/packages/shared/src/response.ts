export interface ResponseConnector {connector_id:string;device_id:string;version:string;config_sha256:string;status:'unverified'|'unavailable'|'ready';observed_at:string;max_ttl_seconds:number}
export interface ResponseAction {schema_version:'response.action.v1';connector_id:string;config_sha256:string;device_id:string;lease_id:string;owner_sha256:string;target_ip:string;requested_at:string;expires_at:string;reason:string}
export const responseStates:Record<string,string>={active:'回读时有效',revoked:'回读时已解除',expired:'回读时已到期',unknown:'状态待核对',pending:'等待核对',ready:'设备已就绪',unverified:'身份待核验',unavailable:'设备不可用'}
export function readyConnector(value:ResponseConnector,now=Date.now()){
 const seen=Date.parse(value?.observed_at),id=/^[a-z0-9][a-z0-9_-]{0,63}$/
 return !!value&&id.test(value.connector_id)&&id.test(value.device_id)&&typeof value.version==='string'&&value.version.length>0&&[...value.version].length<=64&&value.version===value.version.trim()&&!/[\u0000-\u001f\u007f]/.test(value.version)&&/^[a-f0-9]{64}$/.test(value.config_sha256)&&value.status==='ready'&&Number.isFinite(seen)&&now-seen<=35000&&seen-now<=30000&&Number.isSafeInteger(value.max_ttl_seconds)&&value.max_ttl_seconds>=30&&value.max_ttl_seconds<=3600
}
