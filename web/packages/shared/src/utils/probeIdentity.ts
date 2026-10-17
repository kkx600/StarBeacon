export interface ProbeIdentityStatus {
 mode:'managed'|'static';sensor_id:string;registration_id:string;fingerprint_sha256:string
 not_before:string;not_after:string;renew_after:string
}
const id=(value:unknown):value is string=>typeof value==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)
export function validProbeIdentity(value:unknown):value is ProbeIdentityStatus{
 if(!value||typeof value!=='object')return false
 const row=value as Record<string,unknown>
 if(!id(row.sensor_id)||!id(row.registration_id)||!['static','managed'].includes(String(row.mode)))return false
 if(['private_key','key_pem','chain_pem','csr_pem','token'].some(key=>key in row))return false
 if(row.mode==='static')return row.fingerprint_sha256===''
 const dates=[row.not_before,row.renew_after,row.not_after]
 return typeof row.fingerprint_sha256==='string'&&/^[a-f0-9]{64}$/.test(row.fingerprint_sha256)&&dates.every(v=>typeof v==='string'&&Number.isFinite(Date.parse(v)))&&Date.parse(String(row.not_before))<Date.parse(String(row.renew_after))&&Date.parse(String(row.renew_after))<Date.parse(String(row.not_after))
}
