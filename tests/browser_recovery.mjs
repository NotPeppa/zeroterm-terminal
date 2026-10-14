import {selectBrowserTarget} from './browser_targets.mjs';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
const run=promisify(execFile),require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_PACKAGE || 'playwright');
const fixture=JSON.parse(await readFile(process.argv[2],'utf8')),output=process.argv[3],remoteRoot=process.argv[4];
assert.equal(fixture.capacity_rdp_profiles.length,3,'capacity requires independent RDP target logins');
const remoteSource=process.env.BASTION_ACCEPTANCE_REMOTE_SOURCE;
if(process.env.BASTION_ACCEPTANCE_SSH_HOST)assert.match(remoteSource,/^\/var\/tmp\/zt-guac-v2-[a-z0-9-]+\/source$/);
assert.match(fixture.server_id,/^zt-guac-v2-[a-z0-9-]+$/);assert(fixture.recording_faults_enabled);
assert.equal(remoteRoot,'/var/tmp/'+fixture.server_id);await mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true,args:['--ignore-certificate-errors-spki-list='+fixture.public_spki]});
const context=await browser.newContext(),page=await context.newPage();
const result=process.env.BASTION_ACCEPTANCE_RESUME_EVIDENCE?JSON.parse(await readFile(process.env.BASTION_ACCEPTANCE_RESUME_EVIDENCE,'utf8')):{production_ready:false,windows_nla_verified:false,native_os_ime_verified:false,application_image_id:fixture.application_image_id,engine_image_id:fixture.engine_image_id,fixture_server_id:fixture.server_id,baseline:[],faults:{}};
assert.equal(result.fixture_server_id,fixture.server_id);assert.equal(result.application_image_id,fixture.application_image_id);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function poll(read,accept,timeout=30000){const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await read();if(accept(value))return value;await sleep(100);}throw new Error('controlled acceptance poll deadline exceeded');}
async function request(p,resource,body){return p.evaluate(async({resource,body})=>{
  const csrf=document.cookie.split(';').map(row=>row.trim()).find(row=>row.startsWith('bastion_csrf='))?.split('=')[1];
  const response=await fetch('/api/v1'+resource,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  const text=await response.text();return {status:response.status,value:text?JSON.parse(text):null};
},{resource,body});}
async function api(p,resource,body){const response=await request(p,resource,body);assert(response.status>=200 && response.status<300,'API status '+response.status+' for '+resource);return response.value;}
async function login(p,username=fixture.username){
  await p.goto(fixture.origin,{waitUntil:'networkidle'});
  if(await p.locator('#workspace').isVisible())return;
  await p.locator('#username').fill(username);await p.locator('#password').fill(fixture.password);await p.locator('#login').click();
  await p.locator('#workspace').waitFor({state:'visible'});
}
async function connect(p,profile,ready=true){
  const response=await selectBrowserTarget(p,profile.asset_id,profile.account_id);
  assert.equal(response.status(),201);const ticket=await response.json();ticket.ws_token='';
  if(ready)await p.waitForFunction(()=>document.querySelector('#status').textContent.includes('目标显示流已就绪') || document.querySelector('#status').textContent.includes('SSH 终端已就绪'),null,{timeout:50000});
  return ticket.connection_id;
}
async function rec(connection){return poll(()=>api(page,'/recordings?connection_id='+connection),rows=>rows.items.length===1).then(rows=>rows.items[0]);}
async function ended(connection){await poll(()=>api(page,'/connections/'+connection),row=>!['pending','connecting','active','closing'].includes(row.state));return poll(()=>rec(connection),row=>!['preparing','active'].includes(row.state));}
async function disconnect(p,connection){await p.getByRole('button',{name:'断开',exact:true}).click();return poll(()=>rec(connection),row=>row.state==='complete');}
async function replay(p,row){
  await p.evaluate(()=>{location.hash='#/recordings';});await p.getByLabel('录制 ID',{exact:true}).fill(row.id);
  await p.getByRole('button',{name:'播放 / 从头重播',exact:true}).click();
  await p.waitForFunction(()=>document.querySelector('#status').textContent==='只读回放完成。',null,{timeout:60000});
}
function sshArgs(command){return ['-i',process.env.BASTION_ACCEPTANCE_SSH_KEY,'-p',process.env.BASTION_ACCEPTANCE_SSH_PORT || '22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',process.env.BASTION_ACCEPTANCE_SSH_HOST,command];}
async function probe(operation,body={}){
  assert.match(operation,/^[a-z-]+$/);
  const args=[remoteRoot,operation];
  const remote=!!process.env.BASTION_ACCEPTANCE_SSH_HOST;
  const command=remote?sshArgs('python3 '+remoteSource+'/tests/docker_recording_probe.py '+args.join(' ')):['tests/docker_recording_probe.py',...args];
  return new Promise((resolve,reject)=>{
    const child=spawn(remote?'ssh':'python3',command,{stdio:['pipe','pipe','pipe']});let stdout='',stderr='';
    const timer=setTimeout(()=>{child.kill();reject(new Error('controlled fixture operation timeout: '+operation));},300000);
    child.stdout.on('data',bytes=>{stdout+=bytes;});child.stderr.on('data',bytes=>{stderr+=bytes;});child.on('error',error=>{clearTimeout(timer);reject(error);});
    child.on('close',code=>{clearTimeout(timer);if(code)reject(new Error('fixture operation '+operation+' failed: '+stderr));else{try{resolve(JSON.parse(stdout));}catch(error){reject(error);}}});child.stdin.end(JSON.stringify(body));
  });
}
async function resources(){
  const args=['stats','--no-stream','--format','json',fixture.server_id+'-bastion-1',fixture.server_id+'-guacd-1',fixture.server_id+'-target-1',fixture.server_id+'-restored-postgres'];
  const remote=!!process.env.BASTION_ACCEPTANCE_SSH_HOST;
  const text=(await run(remote?'ssh':'docker',remote?sshArgs('docker '+args.join(' ')):args,{timeout:20000})).stdout;
  const session=await browser.newBrowserCDPSession();const processes=(await session.send('SystemInfo.getProcessInfo')).processInfo;await session.detach();
  let memory;
  if(process.platform==='win32'){
    const ids=processes.map(row=>row.id);assert(ids.every(value=>Number.isSafeInteger(value) && value>0));
    memory=JSON.parse((await run('powershell',['-NoProfile','-Command','Get-Process -Id '+ids.join(',')+' -ErrorAction SilentlyContinue | Select-Object Id,WorkingSet64,PrivateMemorySize64 | ConvertTo-Json -Compress'],{timeout:15000})).stdout);
  }else{
    memory=await Promise.all(processes.map(async row=>{const text=await readFile('/proc/'+row.id+'/status','utf8');return {id:row.id,rss_kib:Number(/^VmRSS:\s+(\d+)/m.exec(text)?.[1] || 0)};}));
  }
  return {at:new Date().toISOString(),containers:text.trim().split('\n').map(line=>JSON.parse(line)),browser_processes:processes,browser_memory:memory};
}
function trace(p){const stats={output_blocks:0,output_bytes:0,closed:false,closed_at:0};p.on('websocket',socket=>{socket.on('framereceived',({payload})=>{stats.output_blocks++;stats.output_bytes+=Buffer.from(payload).length;});socket.on('close',()=>{stats.closed=true;stats.closed_at=Date.now();});});return stats;}
const profiles=['ssh','rdp','vnc'].map(protocol=>fixture.profiles.find(row=>row.protocol===protocol));
try{
  await login(page);assert.equal((await api(page,'/info')).server_id,fixture.server_id);
  if(!result.mixed_protocol_measurement?.all_ten_recordings_complete){
  for(const profile of profiles){const connection=await connect(page,profile);await sleep(500);const row=await disconnect(page,connection);await replay(page,row);result.baseline.push(row);}
  // The unused ticket and login are copied by the real backup, then explicitly invalidated.
  const oldTicket=await api(page,'/sessions',{asset_id:profiles[0].asset_id,account_id:profiles[0].account_id,display:{width:1280,height:720,dpi:96}});oldTicket.ws_token='';
  result.restore=await probe('backup-restore');assert.equal((await request(page,'/me')).status,401);
  await context.clearCookies();await login(page);for(const row of result.baseline)await replay(page,row);
  result.restore.old_cookie_rejected=true;result.restore.three_protocol_replay=true;console.log('Cold restore, cookie invalidation and three-protocol replay passed.');
  result.rewrap=await probe('rewrap');await page.reload({waitUntil:'networkidle'});await page.locator('#workspace').waitFor({state:'visible'});
  for(const row of result.baseline)await replay(page,row);
  const rotated=await connect(page,profiles[0]);await disconnect(page,rotated);result.rewrap.real_target_authentication=true;result.rewrap.three_protocol_replay=true;console.log('New-key-only verification, replay and target authentication passed.');
  const contexts=[],live=[];
  try{
    for(let user=0;user<4;user++){
      const username='load-'+user;const who=await api(page,'/admin/users',{username,password:fixture.password,role:'operator'});
      const userProfiles=[profiles[0],fixture.capacity_rdp_profiles[user%3],profiles[2]];
      for(const profile of userProfiles)await api(page,'/admin/grants',{user_id:who.id,asset_id:profile.asset_id,account_id:profile.account_id,expires_at:null});
      const context=await browser.newContext();contexts.push(context);const first=await context.newPage();await login(first,username);
      for(let index=0;index<(user===3?1:3);index++){
        const current=index===0?first:await context.newPage();if(index)await login(current,username);
        const profile=userProfiles[(user*3+index)%3];live.push({page:current,connection:await connect(current,profile),profile});
      }
    }
    for(const item of live)assert.equal((await api(page,'/connections/'+item.connection)).state,'active','a target replaced an existing capacity session');
    const overflow=await request(page,'/sessions',{asset_id:profiles[0].asset_id,account_id:profiles[0].account_id,display:{width:1280,height:720,dpi:96}});
    assert.equal(overflow.status,429);assert.equal(overflow.value.error.code,'CONNECTION_LIMIT');
    result.capacity_limits=await probe('limits');
    const samples=[],started=Date.now();
    for(let sample=0;sample<5;sample++){
      samples.push(await resources());
      for(const item of live){assert.equal((await api(page,'/connections/'+item.connection)).state,'active');const viewport=item.page.locator('.guac-viewport, .terminal-viewport');const box=await viewport.boundingBox();await item.page.mouse.move(box.x+40+sample*10,box.y+40);}
      if(sample<4)await sleep(30000);
    }
    result.mixed_protocol_measurement={connections:10,distribution:{ssh:4,rdp:3,vnc:3},duration_ms:Date.now()-started,eleventh_global_connection_rejected:true,load:'initial display, periodic mouse movement and protocol sync; no throughput claim',samples,sustained_production_capacity_claimed:false};
    for(const item of live){await disconnect(item.page,item.connection);await item.page.screenshot({path:path.join(output,item.connection+'.png')});}
    result.mixed_protocol_measurement.all_ten_recordings_complete=true;console.log('Ten mixed connections, global quota and resource samples passed.');
  }finally{for(const context of contexts)await context.close();}
  }
  await api(page,'/auth/refresh',{});await page.reload({waitUntil:'networkidle'});await page.locator('#workspace').waitFor({state:'visible'});
  for(const mode of ['open','dir-fsync','write','short-write','file-fsync']){
    if(result.faults['startup_'+mode])continue;
    await probe('arm',{mode});const faultPage=await context.newPage();await login(faultPage);const stats=trace(faultPage);
    try{
      const connection=await connect(faultPage,profiles[0],false);const row=await ended(connection);const hits=(await probe('hits')).hits;
      assert(hits.length>0,'fault shim was not exercised: '+mode);assert.notEqual(row.state,'complete');assert.equal(stats.output_blocks,0,'unacknowledged startup output reached browser');
      result.faults['startup_'+mode]={recording_state:row.state,output_blocks:stats.output_blocks,hits};
      console.log('Startup fault passed: '+mode);
    }finally{await probe('arm',{mode:'off'});await faultPage.close();}
  }
  for(const mode of ['write','short-write','file-fsync','blocked-write','blocked-fsync']){
    if(result.faults['active_'+mode])continue;
    const faultPage=await context.newPage();await login(faultPage);const stats=trace(faultPage);const connection=await connect(faultPage,profiles[0]);
    let started;
    try{
      await probe('arm',{mode});started=Date.now();await faultPage.locator('.guac-viewport textarea, .terminal-viewport textarea').focus();await faultPage.keyboard.type('echo fault-output');await faultPage.keyboard.press('Enter');
      await poll(()=>stats.closed,value=>value,15000);const row=await ended(connection);const hits=(await probe('hits')).hits;
      assert(hits.length>0);assert.notEqual(row.state,'complete');const closed=stats.closed_at-started;
      if(mode.startsWith('blocked-'))assert(closed<12000,'ACK deadline did not promptly close transport');
      result.faults['active_'+mode]={closed_ms:closed,clock_start:'after fault control operation completes, before target input',recording_state:row.state,hits};
      console.log('Active fault passed: '+mode);
    }finally{await probe('arm',{mode:'off'});await faultPage.close();}
  }
  let connection;
  if(!result.faults.end_fsync){connection=await connect(page,profiles[0]);
  try{
    await probe('arm',{mode:'file-fsync'});await page.getByRole('button',{name:'断开',exact:true}).click();const row=await ended(connection);
    assert.notEqual(row.state,'complete');const hits=(await probe('hits')).hits;assert(hits.length>0);
    result.faults.end_fsync={recording_state:row.state,hits};
  }finally{await probe('arm',{mode:'off'});}
  }
  if(!result.faults.real_disk_full){await page.evaluate(()=>{location.hash='#/assets';});connection=await connect(page,profiles[0]);
  try{
    const filled=await probe('fill');await page.locator('.guac-viewport textarea, .terminal-viewport textarea').focus();await page.keyboard.type('echo enospc');await page.keyboard.press('Enter');const row=await ended(connection);
    assert.notEqual(row.state,'complete');result.faults.real_disk_full={...filled,recording_state:row.state};
  }finally{await probe('clear-fill');}
  }
  if(!result.faults.database_finalization){await page.evaluate(()=>{location.hash='#/assets';});connection=await connect(page,profiles[0]);
  try{await probe('fail-finalize');await page.getByRole('button',{name:'断开',exact:true}).click();const row=await ended(connection);assert.equal(row.state,'partial');result.faults.database_finalization={recording_state:row.state};}
  finally{await probe('clear-finalize');}
  }
  await page.evaluate(()=>{location.hash='#/assets';});connection=await connect(page,profiles[0]);
  await probe('kill-app');await poll(async()=>{try{return await api(page,'/info');}catch{return null;}},info=>info?.recording?.available);
  const interrupted=await api(page,'/connections/'+connection);assert.equal(interrupted.state,'interrupted');assert.equal((await rec(connection)).state,'partial');result.faults.process_restart={connection_state:interrupted.state,recording_state:'partial'};
  for(const [index,kind] of ['tamper','truncate'].entries()){
    const row=result.baseline[index];await probe(kind,{recording_id:row.id});
    const read=await page.evaluate(async id=>{try{const response=await fetch('/api/v1/recordings/'+id+'/content',{credentials:'same-origin'});try{await response.text();return {status:response.status,clean_eof:response.ok};}catch{return {status:response.status,clean_eof:false};}}catch{return {status:0,clean_eof:false};}},row.id);
    assert(!read.clean_eof);assert.equal((await api(page,'/recordings/'+row.id)).state,'corrupt');result.faults[kind]=read;
  }
  result.retention=await probe('retention',{recording_id:result.baseline[0].id,kept_id:result.baseline[2].id});await page.reload({waitUntil:'networkidle'});await replay(page,result.baseline[2]);result.retention.kept_recording_replays=true;
  delete result.error;result.status='passed-real-recovery-and-fault-components';
}catch(error){result.status='failed';result.error=error.message;await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});throw error;}
finally{await browser.close();await writeFile(path.join(output,'recovery-evidence.json'),JSON.stringify(result,null,2)+'\n');}
console.log(JSON.stringify(result,null,2));
