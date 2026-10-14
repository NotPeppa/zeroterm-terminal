// Sustained high-output SSH stress: flood sessions plus one interactive session measuring echo latency.
// A stress measurement on whatever host runs the fixture, not a capacity or sizing claim.
// Usage: node tests/browser_load.mjs <protected-fixture.json> <evidence-directory>
import {selectBrowserTarget} from './browser_targets.mjs';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
const run=promisify(execFile),require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_PACKAGE || 'playwright');
const fixture=JSON.parse(await readFile(process.argv[2],'utf8')),output=process.argv[3];
assert.match(fixture.server_id,/^zt-guac-v2-[a-z0-9-]+$/);await mkdir(output,{recursive:true});
const DURATION_MS=Number(process.env.BASTION_LOAD_DURATION_MS || 600000),FLOODS=Number(process.env.BASTION_LOAD_FLOODS || 8);
assert(FLOODS>=1 && FLOODS<=9,'flood sessions plus the interactive one must stay within the global limit of 10');
const FLOOD="while :; do head -c 49152 /dev/urandom | base64; done";
const browser=await chromium.launch({headless:true,args:['--ignore-certificate-errors-spki-list='+fixture.public_spki]});
const result={production_ready:false,capacity_claimed:false,application_image_id:fixture.application_image_id,fixture_server_id:fixture.server_id,duration_ms:DURATION_MS,flood_sessions:FLOODS,flood_command:FLOOD,samples:[],echo:[],errors:[]};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function poll(read,accept,timeout=30000){const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await read();if(accept(value))return value;await sleep(200);}throw new Error('load poll deadline exceeded');}
async function api(p,resource,body){return p.evaluate(async({resource,body})=>{
  const csrf=document.cookie.split(';').map(row=>row.trim()).find(row=>row.startsWith('bastion_csrf='))?.split('=')[1];
  const send=()=>fetch('/api/v1'+resource,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  // Like the app: an expired access cookie is refreshed once, then the request is retried.
  let response=await send();
  if(response.status===401){await fetch('/api/v1/auth/refresh',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:'{}'});response=await send();}
  const text=await response.text();if(response.status<200||response.status>=300)throw new Error('API status '+response.status+' for '+resource);return text?JSON.parse(text):null;
},{resource,body});}
async function login(p,username=fixture.username){
  await p.goto(fixture.origin,{waitUntil:'networkidle'});
  if(await p.locator('#workspace').isVisible())return;
  await p.locator('#username').fill(username);await p.locator('#password').fill(fixture.password);await p.locator('#login').click();
  await p.locator('#workspace').waitFor({state:'visible'});
}
async function connect(p,profile){
  const response=await selectBrowserTarget(p,profile.asset_id,profile.account_id);assert.equal(response.status(),201);
  const ticket=await response.json();ticket.ws_token='';
  await p.waitForFunction(()=>document.querySelector('#status').textContent.includes('SSH 终端已就绪'),null,{timeout:50000});
  return ticket.connection_id;
}
const screen=p=>p.evaluate(()=>document.querySelector('.terminal-viewport .xterm-rows')?.textContent ?? '');
async function type(p,text){await p.locator('.terminal-viewport textarea').focus();await p.keyboard.type(text);}
function sshArgs(command){return ['-i',process.env.BASTION_ACCEPTANCE_SSH_KEY,'-p',process.env.BASTION_ACCEPTANCE_SSH_PORT || '22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',process.env.BASTION_ACCEPTANCE_SSH_HOST,command];}
async function stats(){
  const names=['bastion','guacd','postgres','target','proxy'].map(name=>fixture.server_id+'-'+name+'-1');
  const command='docker stats --no-stream --format "{{json .}}" '+names.join(' ');
  const text=process.env.BASTION_ACCEPTANCE_SSH_HOST?(await run('ssh',sshArgs(command),{timeout:30000})).stdout:(await run('sh',['-c',command],{timeout:30000})).stdout;
  return text.trim().split('\n').map(line=>JSON.parse(line)).map(row=>({name:row.Name.slice(fixture.server_id.length+1),cpu:row.CPUPerc,mem:row.MemUsage,pids:row.PIDs,net:row.NetIO,block:row.BlockIO}));
}
const profile=fixture.profiles.find(row=>row.label==='ssh-password');assert(profile);
const contexts=[],floods=[],RUN=Date.now().toString(36);
try{
  const adminContext=await browser.newContext();contexts.push(adminContext);const admin=await adminContext.newPage();await login(admin);
  assert.equal((await api(admin,'/info')).server_id,fixture.server_id);
  for(let user=0;user<Math.ceil(FLOODS/3);user++){
    const username='flood-'+RUN+'-'+user;const who=await api(admin,'/admin/users',{username,password:fixture.password,role:'operator'});
    await api(admin,'/admin/grants',{user_id:who.id,asset_id:profile.asset_id,account_id:profile.account_id,expires_at:null});
    const context=await browser.newContext();contexts.push(context);
    for(let index=0;index<3 && floods.length<FLOODS;index++){
      const p=await context.newPage();p.on('pageerror',error=>result.errors.push(error.message));await login(p,username);
      floods.push({page:p,connection:await connect(p,profile)});
    }
  }
  const interactive=await adminContext.newPage();interactive.on('pageerror',error=>result.errors.push(error.message));await login(interactive);
  const interactiveConnection=await connect(interactive,profile);
  let started=0,n=0;result.baseline_echo=[];
  for(let n=0;n<3;n++)result.baseline_echo.push(await echo(n,'baseline'));
  for(const flood of floods){await type(flood.page,FLOOD);await flood.page.keyboard.press('Enter');}
  started=Date.now();
  async function echo(index,phase){
    const marker='ZT_ECHO_'+phase+'_'+index+'_'+Date.now().toString(36);
    const t0=Date.now();await type(interactive,'echo '+marker);
    await poll(()=>screen(interactive),text=>text.includes(marker),30000);const keystroke_echo_ms=Date.now()-t0;
    const t1=Date.now();await interactive.keyboard.press('Enter');
    await poll(()=>screen(interactive),text=>text.split(marker).length>=3,30000);
    const row={at_ms:Date.now()-(started||Date.now()),keystroke_echo_ms,command_roundtrip_ms:Date.now()-t1};
    await type(interactive,'clear');await interactive.keyboard.press('Enter');return row;
  }
  while(Date.now()-started<DURATION_MS){
    result.echo.push(await echo(n++,'load'));
    if(result.echo.length%3===1){
      const sample={at_ms:Date.now()-started,containers:await stats(),connections:[]};
      for(const flood of [...floods,{connection:interactiveConnection}])sample.connections.push((await api(admin,'/connections/'+flood.connection)).state);
      assert(sample.connections.every(state=>state==='active'),'a session dropped under load: '+sample.connections.join(','));
      result.samples.push(sample);console.log('sample '+JSON.stringify({at_ms:sample.at_ms,bastion:sample.containers.find(c=>c.name==='bastion'),echo:result.echo.at(-1)}));
    }
    await sleep(10000);
  }
  result.measured_ms=Date.now()-started;
  for(const flood of floods){await flood.page.locator('.terminal-viewport textarea').focus();await flood.page.keyboard.press('Control+c');}
  const recordings=[];
  for(const item of [...floods,{page:interactive,connection:interactiveConnection}]){
    await item.page.getByRole('button',{name:'断开',exact:true}).click();
    const row=await poll(async()=>(await api(admin,'/recordings?connection_id='+item.connection)).items[0],row=>row && row.state==='complete',120000);
    recordings.push({connection:item.connection,state:row.state,bytes:row.bytes});
  }
  result.recordings=recordings;result.recorded_bytes_total=recordings.reduce((sum,row)=>sum+Number(row.bytes),0);
  result.recorded_mib_per_second=+(result.recorded_bytes_total/1048576/(result.measured_ms/1000)).toFixed(3);
  const sorted=key=>result.echo.map(row=>row[key]).sort((a,b)=>a-b),p=(values,q)=>values[Math.min(values.length-1,Math.floor(q*values.length))];
  for(const key of ['keystroke_echo_ms','command_roundtrip_ms'])result[key+'_summary']={p50:p(sorted(key),0.5),p95:p(sorted(key),0.95),max:sorted(key).at(-1),n:result.echo.length};
  const last=recordings.at(-1);await admin.evaluate(()=>{location.hash='#/recordings';});await admin.getByLabel('录制 ID',{exact:true}).fill((await api(admin,'/recordings?connection_id='+last.connection)).items[0].id);
  await admin.getByRole('button',{name:'播放 / 从头重播',exact:true}).click();
  // Replay is real time with no seeking, so a session as long as the load phase replays for about as long.
  await admin.waitForFunction(()=>document.querySelector('#status').textContent==='只读回放完成。',null,{timeout:result.measured_ms+180000});result.interactive_replay_verified=true;
  assert.deepEqual(result.errors,[]);result.status='passed-ssh-high-output-stress';
}catch(error){result.status='failed';result.error=String(error?.stack||error);throw error;}
finally{for(const context of contexts)await context.close().catch(()=>{});await browser.close();await writeFile(path.join(output,'load-evidence.json'),JSON.stringify(result,null,2)+'\n');}
