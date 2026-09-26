import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {diffPolicies,TOOL_ID,LIMITS} from '../src/index.mjs';

const statement=()=>({Sid:'ReadObjects',Effect:'Allow',Action:['s3:GetObject'],Resource:['arn:aws:s3:::example-bucket/*'],Condition:{StringEquals:{'aws:RequestedRegion':'us-east-1'}}});
const document=()=>({schemaVersion:'1',complete:true,policy:{Version:'2012-10-17',Statement:[statement()]}});

test('identical supported identity policies pass without an effective-permissions claim',()=>{
  const r=diffPolicies(document(),document(),{now:()=>0});assert.equal(TOOL_ID,'iam-least-privilege-diff');assert.equal(r.status,'pass');assert.equal(r.summary.checked,1);assert.equal(r.effectivePermissions,'not-evaluated');assert.deepEqual(r.findings,[]);
});
test('new wildcard action and resource are surfaced as a failing broadening',()=>{
  const before=document(),after=document();after.policy.Statement[0].Action.push('s3:*');after.policy.Statement[0].Resource.push('*');
  const r=diffPolicies(before,after,{now:()=>0});assert.equal(r.status,'fail');assert.ok(r.findings.some(f=>f.ruleId==='wildcard-added'));assert.ok(r.findings.some(f=>f.ruleId==='action-added'));assert.ok(r.findings.some(f=>f.ruleId==='resource-added'));assert.doesNotMatch(JSON.stringify(r),/example-bucket|us-east-1/);
});
test('removed condition is reported as a failing constraint removal',()=>{
  const after=document();delete after.policy.Statement[0].Condition;
  const r=diffPolicies(document(),after,{now:()=>0});assert.equal(r.status,'fail');assert.equal(r.findings[0].ruleId,'constraint-removed');
});
test('removed action and resource are explained without claiming new privilege',()=>{
  const before=document(),after=document();before.policy.Statement[0].Action.push('s3:ListBucket');before.policy.Statement[0].Resource.push('arn:aws:s3:::other-bucket');
  const r=diffPolicies(before,after,{now:()=>0});assert.equal(r.status,'pass');assert.deepEqual(r.findings.map(f=>f.ruleId),['action-removed','resource-removed']);
});
test('unsupported IAM semantics and absent coverage are incomplete',()=>{
  const after=document();after.policy.Statement[0].NotAction=['s3:DeleteObject'];assert.equal(diffPolicies(document(),after,{now:()=>0}).status,'incomplete');
  const deny=document();deny.policy.Statement[0].Effect='Deny';assert.equal(diffPolicies(document(),deny,{now:()=>0}).status,'incomplete');
  const partial=document();delete partial.complete;assert.equal(diffPolicies(partial,document(),{now:()=>0}).status,'incomplete');
});
test('array and object key order do not make an unchanged policy fail',()=>{
  const a=document(),b=document();a.policy.Statement[0].Action=['s3:GetObject','s3:ListBucket'];b.policy.Statement[0].Action=['s3:ListBucket','s3:GetObject'];
  assert.equal(diffPolicies(a,b,{now:()=>0}).status,'pass');
});
test('duplicate Sid and changed equality value cannot silently pass',()=>{
  const a=document();a.policy.Statement.push(structuredClone(a.policy.Statement[0]));assert.equal(diffPolicies(a,document(),{now:()=>0}).status,'incomplete');
  const b=document();b.policy.Statement[0].Condition.StringEquals['aws:RequestedRegion']='eu-west-1';assert.equal(diffPolicies(document(),b,{now:()=>0}).status,'incomplete');
});
test('statement, depth, and clock limits accept N and reject N+1',()=>{
  const a=document(),b=document();a.policy.Statement=Array.from({length:LIMITS.statements},(_,i)=>({...statement(),Sid:`S${i}`}));b.policy.Statement=structuredClone(a.policy.Statement);
  assert.equal(diffPolicies(a,b,{now:()=>0}).status,'pass');a.policy.Statement.push({...statement(),Sid:'Extra'});assert.equal(diffPolicies(a,b,{now:()=>0}).findings[0].ruleId,'record-limit');
  const c=document(),d=document();let x=c;for(let i=0;i<LIMITS.depth;i++){x.extra={};x=x.extra;}assert.equal(diffPolicies(c,d,{now:()=>0}).status,'pass');x.extra={};assert.equal(diffPolicies(c,d,{now:()=>0}).findings[0].ruleId,'depth-limit');
  const clock=n=>{let first=true;return()=>{if(first){first=false;return 0;}return n;};};assert.equal(diffPolicies(document(),document(),{now:clock(5000)}).status,'pass');assert.equal(diffPolicies(document(),document(),{now:clock(5001)}).findings[0].ruleId,'time-limit');
});
test('question-mark action wildcard is surfaced',()=>{
  const after=document();after.policy.Statement[0].Action.push('s3:Get?bject');
  assert.ok(diffPolicies(document(),after,{now:()=>0}).findings.some(f=>f.ruleId==='wildcard-added'));
});
test('action resource and condition bounds accept N and reject N+1',()=>{
  for(const [field,limit] of [['Action',LIMITS.actions],['Resource',LIMITS.resources]]){
    const a=document(),b=document();a.policy.Statement[0][field]=Array.from({length:limit},(_,i)=>`${field}${i}`);b.policy.Statement[0][field]=[...a.policy.Statement[0][field]];
    assert.equal(diffPolicies(a,b,{now:()=>0}).status,'pass',field);
    b.policy.Statement[0][field].push(`${field}extra`);
    assert.equal(diffPolicies(a,b,{now:()=>0}).findings[0].ruleId,'record-limit',field);
  }
  const a=document(),b=document();a.policy.Statement[0].Condition.StringEquals=Object.fromEntries(Array.from({length:LIMITS.conditionKeys},(_,i)=>[`k${i}`,'v']));b.policy.Statement[0].Condition=structuredClone(a.policy.Statement[0].Condition);
  assert.equal(diffPolicies(a,b,{now:()=>0}).status,'pass');b.policy.Statement[0].Condition.StringEquals.extra='v';assert.equal(diffPolicies(a,b,{now:()=>0}).findings[0].ruleId,'record-limit');
});
function cli(args){return spawnSync(process.execPath,['bin/iam-least-privilege-diff.mjs',...args],{cwd:path.resolve(import.meta.dirname,'..'),encoding:'utf8'});}
function fixture(run){const root=fs.mkdtempSync(path.join(os.tmpdir(),'iam-diff-'));try{return run(root);}finally{fs.rmSync(root,{recursive:true,force:true});}}
test('CLI accepts contained complete files and reports unsupported policy as incomplete',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'before.json'),JSON.stringify(document()));fs.writeFileSync(path.join(root,'after.json'),JSON.stringify(document()));
  let r=cli(['--root',root,'--before','before.json','--after','after.json']);assert.equal(r.status,0);assert.equal(JSON.parse(r.stdout).status,'pass');
  const bad=document();bad.policy.Statement[0].NotResource=['*'];fs.writeFileSync(path.join(root,'after.json'),JSON.stringify(bad));r=cli(['--root',root,'--before','before.json','--after','after.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');
}));
test('CLI rejects duplicate decoded JSON keys and read-side escape',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'before.json'),JSON.stringify(document()));fs.writeFileSync(path.join(root,'after.json'),'{"schemaVersion":"1","complete":false,"compl\\u0065te":true,"policy":{}}');
  let r=cli(['--root',root,'--before','before.json','--after','after.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');
  const outside=fs.mkdtempSync(path.join(os.tmpdir(),'iam-out-'));try{fs.writeFileSync(path.join(outside,'policy.json'),JSON.stringify(document()));fs.symlinkSync(path.join(outside,'policy.json'),path.join(root,'escape.json'));r=cli(['--root',root,'--before','before.json','--after','escape.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');}finally{fs.rmSync(outside,{recursive:true,force:true});}
}));
test('CLI uses strict UTF-8, enforces both byte limits, and leaves stdout empty on bad options',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'before.json'),JSON.stringify(document()));fs.writeFileSync(path.join(root,'after.json'),JSON.stringify(document()));
  let r=cli(['--root',root,'--before','before.json','--after','after.json','--bogus']);assert.equal(r.status,2);assert.equal(r.stdout,'');
  for(const [name,limit] of [['before.json',LIMITS.beforeBytes],['after.json',LIMITS.afterBytes]]){
    const valid=JSON.stringify(document());fs.writeFileSync(path.join(root,name),valid+' '.repeat(limit-Buffer.byteLength(valid)));r=cli(['--root',root,'--before','before.json','--after','after.json']);assert.equal(r.status,0);
    fs.appendFileSync(path.join(root,name),' ');r=cli(['--root',root,'--before','before.json','--after','after.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).findings[0].ruleId,'byte-limit');fs.writeFileSync(path.join(root,name),valid);
  }
  fs.writeFileSync(path.join(root,'after.json'),Buffer.from([0xff]));r=cli(['--root',root,'--before','before.json','--after','after.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');
}));
test('invalid root is configuration failure with empty stdout; missing named input is incomplete',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'before.json'),JSON.stringify(document()));
  let r=cli(['--root',path.join(root,'missing'),'--before','before.json','--after','after.json']);assert.equal(r.status,2);assert.equal(r.stdout,'');
  r=cli(['--root',root,'--before','before.json','--after','missing.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');assert.equal(JSON.parse(r.stdout).findings[0].ruleId,'input-unreadable');
}));
