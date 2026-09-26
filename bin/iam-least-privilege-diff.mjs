#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {TextDecoder} from 'node:util';
import {diffPolicies,incomplete,LIMITS} from '../src/index.mjs';

function options(argv){
  const result={};
  if(argv.length!==6)return null;
  for(let i=0;i<argv.length;i+=2){
    const key=argv[i];
    if(!['--root','--before','--after'].includes(key)||Object.hasOwn(result,key)||!argv[i+1])return null;
    result[key]=argv[i+1];
  }
  return Object.keys(result).length===3?result:null;
}
function duplicateKeys(text){
  const stack=[];
  for(const match of text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\],:]/gs)){
    const token=match[0],top=stack.at(-1);
    if(token==='{'){stack.push({kind:'object',key:true,seen:new Set()});continue;}
    if(token==='['){stack.push({kind:'array'});continue;}
    if(token==='}'||token===']'){stack.pop();continue;}
    if(token===','){if(top?.kind==='object')top.key=true;continue;}
    if(token===':')continue;
    if(top?.kind==='object'&&top.key){const key=JSON.parse(token);if(top.seen.has(key))return true;top.seen.add(key);top.key=false;}
  }
  return false;
}
function contained(root,target){return target!==root&&target.startsWith(root+path.sep);}
function read(root,relative,role,limit){
  if(path.isAbsolute(relative)||relative.length===0)return {error:'input-unreadable'};
  let target;
  try{target=fs.realpathSync(path.resolve(root,relative));if(!contained(root,target)||!fs.statSync(target).isFile())return {error:'input-unreadable'};}
  catch{return {error:'input-unreadable'};}
  let raw;
  try{raw=fs.readFileSync(target);}catch{return {error:'input-unreadable'};}
  if(raw.length>limit)return {error:'byte-limit'};
  try{
    const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);
    const value=JSON.parse(text);
    if(duplicateKeys(text))return {error:'input-invalid'};
    return {value};
  }catch{return {error:'input-invalid'};}
}
export function main(argv,now=()=>performance.now()){
  const args=options(argv);
  if(!args){process.stderr.write('Usage: iam-least-privilege-diff --root DIR --before FILE --after FILE\n');return 2;}
  let root;
  try{root=fs.realpathSync(args['--root']);if(!fs.statSync(root).isDirectory())throw Error();}
  catch{process.stderr.write('Invalid root.\n');return 2;}
  const before=read(root,args['--before'],'@before',LIMITS.beforeBytes);
  if(before.error){process.stdout.write(JSON.stringify(incomplete(before.error,'@before'))+'\n');return 2;}
  const after=read(root,args['--after'],'@after',LIMITS.afterBytes);
  if(after.error){process.stdout.write(JSON.stringify(incomplete(after.error,'@after'))+'\n');return 2;}
  const result=diffPolicies(before.value,after.value,{now});
  process.stdout.write(JSON.stringify(result)+'\n');
  return result.status==='pass'?0:result.status==='fail'?1:2;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(new URL(import.meta.url)))process.exitCode=main(process.argv.slice(2));
