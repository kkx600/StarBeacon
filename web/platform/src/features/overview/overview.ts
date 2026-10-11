export interface Bucket {key:string;count:string}
export interface Distribution {buckets:readonly Bucket[];other:string;error_upper_bound:string}
export interface Overview {
  window:{start:string;end:string};observed_at:string
  events:{total:string;interval:'hour'|'day';trend:Bucket[];severity:Distribution;protocols:Distribution;rules:Distribution;sensors:Distribution}
  inventory:{assets:string;groups:string;networks:string;sensors:string;online:string;offline:string;disabled:string}
  limitations:string[]
}
export function validOverview(value:unknown):value is Overview{
 const record=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v)
 const date=(v:unknown)=>typeof v==='string'&&Number.isFinite(Date.parse(v))
 const count=(v:unknown)=>typeof v==='string'&&/^(0|[1-9][0-9]{0,18})$/.test(v)&&BigInt(v)<=9223372036854775807n
 if(!record(value)||!record(value.window)||!date(value.window.start)||!date(value.window.end)||Date.parse(String(value.window.end))<=Date.parse(String(value.window.start))||!date(value.observed_at)||!record(value.events)||!record(value.inventory)||!count(value.events.total)||!['hour','day'].includes(String(value.events.interval))||!Array.isArray(value.events.trend)||value.events.trend.length>49||!value.events.trend.every(b=>record(b)&&date(b.key)&&count(b.count))||!Array.isArray(value.limitations)||value.limitations.length>20||!value.limitations.every(v=>typeof v==='string'&&v.length<=2048))return false
 if(!['assets','groups','networks','sensors','online','offline','disabled'].every(key=>count((value.inventory as Record<string,unknown>)[key])))return false
 return ['severity','protocols','rules','sensors'].every(key=>{const d=(value.events as Record<string,unknown>)[key];return record(d)&&count(d.other)&&count(d.error_upper_bound)&&Array.isArray(d.buckets)&&d.buckets.length<=10&&d.buckets.every(b=>record(b)&&typeof b.key==='string'&&b.key.length<=512&&count(b.count))})
}
export function countText(value:string):string {
  if(!/^\d+$/.test(value))return '未获取'
  const count=BigInt(value)
  for(const [unit,scale] of [['万亿',1000000000000n],['亿',100000000n],['万',10000n]] as const){
    if(count>=scale){const whole=count/scale,fraction=count%scale*100n/scale;return `${whole}.${fraction.toString().padStart(2,'0').replace(/0+$/,'')||'0'} ${unit}`}
  }
  return count.toLocaleString('zh-CN')
}
export const severityName:Record<string,string>={high:'高危',medium:'中危',low:'低危',unknown:'未知'}
export function percentage(count:string,total:string):number {
  if(!/^\d+$/.test(count)||!/^\d+$/.test(total)||BigInt(total)===0n)return 0
  return Math.min(100,Number(BigInt(count)*10000n/BigInt(total))/100)
}
