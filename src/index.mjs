export const TOOL_ID='iam-least-privilege-diff';
export const LIMITS=Object.freeze({beforeBytes:524288,afterBytes:524288,statements:1000,actions:1000,resources:1000,conditionKeys:100,depth:16,milliseconds:5000});
export const RULE_SEVERITY=Object.freeze({'input-unreadable':'warning','input-invalid':'warning','export-incomplete':'warning','byte-limit':'warning','record-limit':'warning','depth-limit':'warning','time-limit':'warning','unsupported-semantics':'warning','duplicate-sid':'warning','condition-changed':'warning','statement-added':'error','action-added':'error','resource-added':'error','wildcard-added':'error','constraint-removed':'error','statement-removed':'info','action-removed':'info','resource-removed':'info','condition-added':'info'});
const MESSAGES=Object.freeze({'input-unreadable':'Input could not be read, decoded, or parsed.','input-invalid':'Policy document envelope is invalid.','export-incomplete':'Policy document does not assert complete coverage.','byte-limit':'Input exceeds its declared byte limit.','record-limit':'Policy record count exceeds a declared limit.','depth-limit':'JSON nesting exceeds depth 16.','time-limit':'Evaluation exceeded 5000 milliseconds.','unsupported-semantics':'Policy uses syntax outside the supported identity-policy subset.','duplicate-sid':'Statement identity is duplicated.','condition-changed':'Equality condition values changed; direction is not inferred.','statement-added':'Allow statement was added.','action-added':'Allowed action was added.','resource-added':'Resource selector was added.','wildcard-added':'A new wildcard-bearing selector was added.','constraint-removed':'An equality constraint was removed.','statement-removed':'Allow statement was removed.','action-removed':'Allowed action was removed.','resource-removed':'Resource selector was removed.','condition-added':'An equality constraint was added.'});
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const safe=(x,max=512)=>typeof x==='string'&&x.length>0&&x.length<=max&&x.trim().length>0&&!/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\p{Cf}]/u.test(x);
function finding(ruleId,file,pointer=''){if(!Object.hasOwn(RULE_SEVERITY,ruleId))throw Error('unknown rule');return {ruleId,severity:RULE_SEVERITY[ruleId],message:MESSAGES[ruleId],location:{file,pointer}};}
function report(findings,checked=0){findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));const status=findings.some(f=>f.severity==='warning')?'incomplete':findings.some(f=>f.severity==='error')?'fail':'pass';return {schemaVersion:'1',tool:TOOL_ID,status,summary:{checked,errors:findings.filter(f=>f.severity==='error').length,warnings:findings.filter(f=>f.severity==='warning').length},effectivePermissions:'not-evaluated',findings};}
export function incomplete(ruleId,file){return report([finding(ruleId,file)]);}
function tooDeep(value){const stack=[[value,0]];while(stack.length){const [item,depth]=stack.pop();if(depth>LIMITS.depth)return true;if(item&&typeof item==='object')for(const child of Object.values(item))stack.push([child,depth+1]);}return false;}
function validEnvelope(x){return object(x)&&x.schemaVersion==='1'&&(x.complete===undefined||typeof x.complete==='boolean')&&object(x.policy);}
const list=x=>typeof x==='string'?[x]:Array.isArray(x)?x:null;
function normalizeCondition(value,file,pointer,findings){
  if(value===undefined)return new Map();
  if(!object(value)||Object.keys(value).some(x=>x!=='StringEquals')||!object(value.StringEquals)){findings.push(finding('unsupported-semantics',file,`${pointer}/Condition`));return null;}
  const entries=Object.entries(value.StringEquals);
  if(entries.length>LIMITS.conditionKeys){findings.push(finding('record-limit',file,`${pointer}/Condition`));return null;}
  const result=new Map();
  for(const [key,raw] of entries){
    const values=list(raw);
    if(!safe(key,256)||!values||values.length===0||values.length>LIMITS.conditionKeys||values.some(x=>!safe(x)||x.includes('${'))){findings.push(finding('unsupported-semantics',file,`${pointer}/Condition`));return null;}
    result.set(key,new Set(values));
  }
  return result;
}
function normalizedDocument(doc,file,findings,timed){
  const body=doc.policy;
  if(body.Version!=='2012-10-17'||Object.keys(body).some(x=>!['Version','Statement'].includes(x))){findings.push(finding('unsupported-semantics',file,'/policy'));return null;}
  const statements=object(body.Statement)?[body.Statement]:Array.isArray(body.Statement)?body.Statement:null;
  if(!statements){findings.push(finding('input-invalid',file,'/policy/Statement'));return null;}
  if(statements.length>LIMITS.statements){findings.push(finding('record-limit',file,'/policy/Statement'));return null;}
  const map=new Map();
  for(const [i,item] of statements.entries()){
    if(timed()){findings.push(finding('time-limit',file));return null;}
    const pointer=`/policy/Statement/${i}`;
    if(!object(item)||!safe(item.Sid,128)||item.Effect!=='Allow'||Object.keys(item).some(x=>!['Sid','Effect','Action','Resource','Condition'].includes(x))){findings.push(finding('unsupported-semantics',file,pointer));continue;}
    const actions=list(item.Action),resources=list(item.Resource);
    if(!actions||!resources||actions.length===0||resources.length===0||actions.some(x=>!safe(x,256)||x.includes('${'))||resources.some(x=>!safe(x)||x.includes('${'))){findings.push(finding('unsupported-semantics',file,pointer));continue;}
    if(actions.length>LIMITS.actions||resources.length>LIMITS.resources){findings.push(finding('record-limit',file,pointer));continue;}
    const condition=normalizeCondition(item.Condition,file,pointer,findings);
    if(!condition)continue;
    if(map.has(item.Sid)){findings.push(finding('duplicate-sid',file,pointer));continue;}
    map.set(item.Sid,{actions:new Set(actions),resources:new Set(resources),condition,i});
  }
  return map;
}
const setEqual=(a,b)=>a.size===b.size&&[...a].every(x=>b.has(x));

export function diffPolicies(before,after,{now=()=>performance.now()}={}){
  const start=now(),findings=[];const timed=()=>now()-start>LIMITS.milliseconds;
  if(tooDeep(before))findings.push(finding('depth-limit','@before'));
  if(tooDeep(after))findings.push(finding('depth-limit','@after'));
  if(findings.length)return report(findings);
  if(!validEnvelope(before))findings.push(finding('input-invalid','@before'));
  if(!validEnvelope(after))findings.push(finding('input-invalid','@after'));
  if(findings.length)return report(findings);
  if(before.complete!==true)findings.push(finding('export-incomplete','@before','/complete'));
  if(after.complete!==true)findings.push(finding('export-incomplete','@after','/complete'));
  if(findings.length)return report(findings);
  const a=normalizedDocument(before,'@before',findings,timed),b=normalizedDocument(after,'@after',findings,timed);
  if(findings.length)return report(findings);
  let checked=0;
  for(const [sid,old] of a){
    if(timed())return incomplete('time-limit','@before');
    if(!b.has(sid)){findings.push(finding('statement-removed','@before',`/policy/Statement/${old.i}`));continue;}
    checked++;
    const current=b.get(sid),pointer=`/policy/Statement/${current.i}`;
    const addedActions=[...current.actions].filter(x=>!old.actions.has(x)),removedActions=[...old.actions].filter(x=>!current.actions.has(x));
    const addedResources=[...current.resources].filter(x=>!old.resources.has(x)),removedResources=[...old.resources].filter(x=>!current.resources.has(x));
    if(addedActions.length)findings.push(finding('action-added','@after',`${pointer}/Action`));
    if(removedActions.length)findings.push(finding('action-removed','@before',`/policy/Statement/${old.i}/Action`));
    if(addedResources.length)findings.push(finding('resource-added','@after',`${pointer}/Resource`));
    if(removedResources.length)findings.push(finding('resource-removed','@before',`/policy/Statement/${old.i}/Resource`));
    if([...addedActions,...addedResources].some(x=>/[*?]/.test(x)))findings.push(finding('wildcard-added','@after',pointer));
    for(const key of old.condition.keys()){
      if(!current.condition.has(key))findings.push(finding('constraint-removed','@after',`${pointer}/Condition`));
      else if(!setEqual(old.condition.get(key),current.condition.get(key)))findings.push(finding('condition-changed','@after',`${pointer}/Condition`));
    }
    for(const key of current.condition.keys())if(!old.condition.has(key))findings.push(finding('condition-added','@after',`${pointer}/Condition`));
  }
  for(const [sid,item] of b)if(!a.has(sid)){
    if(timed())return incomplete('time-limit','@after');
    const pointer=`/policy/Statement/${item.i}`;
    findings.push(finding('statement-added','@after',pointer));
    if([...item.actions,...item.resources].some(x=>/[*?]/.test(x)))findings.push(finding('wildcard-added','@after',pointer));
  }
  if(timed())return incomplete('time-limit','@after');
  return report(findings,checked||(!a.size&&!b.size?1:0));
}
