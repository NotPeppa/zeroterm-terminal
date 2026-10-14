// Indefinite recording I/O stall: a recording write/fsync that never returns must not wedge the service.
// Usage: node tests/browser_stall.mjs <protected-fixture.json> <evidence-directory> <remote-fixture-directory>
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
const remoteSource=process.env.BASTION_ACCEPTANCE_REMOTE_SOURCE;
if(process.env.BASTION_ACCEPTANCE_SSH_HOST)assert.match(remoteSource,/^\/var\/tmp\/zt-guac-v2-[a-z0-9-]+\/source$/);
assert.match(fixture.server_id,/^zt-guac-v2-[a-z0-9-]+$/);assert(fixture.recording_faults_enabled);
assert.equal(remoteRoot,'/var/tmp/'+fixture.server_id);await mkdir(output,{recursive:true});
const HOLD_MS=Number(process.env.BASTION_STALL_HOLD_MS || 90000);
const browser=await chromium.launch({headless:true,args:['--ignore-certificate-errors-spki-list='+fixture.public_spki]});
const context=await browser.newContext(),page=await context.newPage();
const result={production_ready:false,application_image_id:fixture.application_image_id,fixture_server_id:fixture.server_id,hold_ms:HOLD_MS,modes:{}};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function poll(read,accept,timeout=30000){const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await read();if(accept(value))return value;await sleep(100);}throw new Error('controlled stall poll deadline exceeded');}
async function request(p,resource,body){return p.evaluate(async({resource,body})=>{
  const csrf=document.cookie.split(';').map(row=>row.trim()).find(row=>row.startsWith('bastion_csrf='))?.split('=')[1];
  const response=await fetch('/api/v1'+resource,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  const text=await response.text();return {status:response.status,value:text?JSON.parse(text):null};
},{resource,body});}
async function api(p,resource,body){const response=await request(p,resource,body);assert(response.status>=200 && response.status<300,'API status '+response.status+' for '+resource);return response.value;}
async function login(p){
  await p.goto(fixture.origin,{waitUntil:'networkidle'});
  if(await p.locator('#workspace').isVisible())return;
  await p.locator('#username').fill(fixture.username);await p.locator('#password').fill(fixture.password);await p.locator('#login').click();
  await p.locator('#workspace').waitFor({state:'visible'});
}
const ready=()=>document.querySelector('#status').textContent.includes('SSH 终端已就绪');
async function connect(p,profile,wait=true){
  const response=await selectBrowserTarget(p,profile.asset_id,profile.account_id);
  assert.equal(response.status(),201);const ticket=await response.json();ticket.ws_token='';
  if(wait)await p.waitForFunction(ready,null,{timeout:50000});
  return ticket.connection_id;
}
const rec=connection=>poll(()=>api(page,'/recordings?connection_id='+connection),rows=>rows.items.length===1).then(rows=>rows.items[0]);
const samples=[];
async function timed(resource){const t=Date.now();try{const value=await api(page,resource);samples.push({resource,ms:Date.now()-t,state:value?.state??value?.items?.[0]?.state});return value;}catch(error){samples.push({resource,ms:Date.now()-t,error:String(error).slice(0,200)});throw error;}}
// While the I/O is stuck the recorder deliberately waits before sealing metadata, so only the
// connection must end; the recording must merely not claim completeness until the stall is released.
async function closedNow(connection,timeout=30000){
  const row=await poll(()=>timed('/connections/'+connection),row=>!['pending','connecting','active','closing'].includes(row.state),timeout);
  return {connection_state:row.state,recording_state:(await rec(connection)).state};
}
async function ended(connection,timeout=30000){
  const row=await poll(()=>timed('/connections/'+connection),row=>!['pending','connecting','active','closing'].includes(row.state),timeout);
  return {connection_state:row.state,recording:await poll(()=>rec(connection),row=>!['preparing','active'].includes(row.state),timeout)};
}
function sshArgs(command){return ['-i',process.env.BASTION_ACCEPTANCE_SSH_KEY,'-p',process.env.BASTION_ACCEPTANCE_SSH_PORT || '22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',process.env.BASTION_ACCEPTANCE_SSH_HOST,command];}
async function probe(operation,body={}){
  assert.match(operation,/^[a-z-]+$/);
  const args=[remoteRoot,operation],remote=!!process.env.BASTION_ACCEPTANCE_SSH_HOST;
  const command=remote?sshArgs('python3 '+remoteSource+'/tests/docker_recording_probe.py '+args.join(' ')):['tests/docker_recording_probe.py',...args];
  return new Promise((resolve,reject)=>{
    const child=spawn(remote?'ssh':'python3',command,{stdio:['pipe','pipe','pipe']});let stdout='',stderr='';
    child.stdout.on('data',bytes=>{stdout+=bytes;});child.stderr.on('data',bytes=>{stderr+=bytes;});child.on('error',reject);
    child.on('close',code=>{if(code)reject(new Error('fixture operation '+operation+' failed: '+stderr));else{try{resolve(JSON.parse(stdout));}catch(error){reject(error);}}});child.stdin.end(JSON.stringify(body));
  });
}
async function threads(){
  const name=fixture.server_id+'-bastion-1';assert.match(name,/^[a-z0-9-]+$/);
  const command="grep '^Threads:' /proc/$(docker inspect -f '{{.State.Pid}}' "+name+")/status";
  const text=process.env.BASTION_ACCEPTANCE_SSH_HOST?(await run('ssh',sshArgs(command),{timeout:15000})).stdout:(await run('sh',['-c',command])).stdout;
  return Number(/Threads:\s+(\d+)/.exec(text)[1]);
}
function trace(p){const stats={frames:0,closed:false,closed_at:0};p.on('websocket',socket=>{socket.on('framereceived',()=>{stats.frames++;});socket.on('close',()=>{stats.closed=true;stats.closed_at=Date.now();});});return stats;}
const profile=fixture.profiles.find(row=>row.label==='ssh-password');assert(profile);
try{
  await login(page);assert.equal((await api(page,'/info')).server_id,fixture.server_id);
  for(const mode of ['stuck-write','stuck-fsync']){
    const row={threads_before:await threads()};const live=await context.newPage();await login(live);const stats=trace(live);
    const connection=await connect(live,profile);let armed=false;
    try{
      await probe('arm',{mode});armed=true;const started=Date.now();
      await live.locator('.terminal-viewport textarea').focus();await live.keyboard.type('echo stall-output-'+mode);await live.keyboard.press('Enter');
      await poll(()=>stats.closed,value=>value,20000);row.live_session_closed_ms=stats.closed_at-started;
      assert(row.live_session_closed_ms<12000,'a stalled recording kept the live session open');
      const live_end=await closedNow(connection,30000);
      assert.notEqual(live_end.recording_state,'complete');row.live_during_stall=live_end;
      // While the I/O is still stuck, the rest of the service must keep working.
      const fresh=await browser.newContext(),other=await fresh.newPage();
      try{
        const t0=Date.now();await login(other);row.fresh_login_during_stall_ms=Date.now()-t0;
        const health=await other.evaluate(async()=>{const r=await fetch('/health/ready');return {status:r.status,body:await r.text()};});
        row.health_during_stall=health;assert.equal(health.status,200);
        assert.equal((await api(other,'/info')).server_id,fixture.server_id);
        const otherStats=trace(other);const second=await connect(other,profile,false);const t1=Date.now();
        const second_end=await closedNow(second,60000);row.second_session_end_ms=Date.now()-t1;
        assert.notEqual(second_end.recording_state,'complete');
        assert(!(await other.evaluate(ready)),'a session started during the stall reached ready');
        row.second_session={...second_end,frames:otherStats.frames};row.second_connection=second;
      }finally{await fresh.close();}
      const remaining=HOLD_MS-(Date.now()-started);if(remaining>0)await sleep(remaining);
      row.stuck_held_ms=Date.now()-started;row.threads_during_stall=await threads();
      row.hits=(await probe('hits')).hits;assert(row.hits.some(hit=>hit.includes('stuck')),'stuck mode was not exercised');
      assert.equal((await api(page,'/me')).user.username,fixture.username);
    }finally{if(armed)await probe('arm',{mode:'off'});await live.close();}
    // Released: the stuck recordings must now seal as incomplete, never complete.
    const settled=await ended(connection,60000);assert(['partial','failed'].includes(settled.recording.state));
    row.live_after_release={connection_state:settled.connection_state,recording_state:settled.recording.state};
    if(row.second_connection){const second=await ended(row.second_connection,60000);assert.notEqual(second.recording.state,'complete');row.second_after_release=second.recording.state;delete row.second_connection;}
    // After release the service must accept and fully record a new session.
    const after=await context.newPage();await login(after);
    try{
      const connection=await connect(after,profile);
      await after.locator('.terminal-viewport textarea').focus();await after.keyboard.type('echo stall-released');await after.keyboard.press('Enter');
      await after.waitForFunction(()=>(document.querySelector('.terminal-viewport .xterm-rows')?.textContent.match(/stall-released/g)??[]).length>=2,null,{timeout:20000});
      await after.getByRole('button',{name:'断开',exact:true}).click();
      row.after_release_recording=(await poll(()=>rec(connection),r=>r.state==='complete',30000)).state;
    }finally{await after.close();}
    await sleep(3000);row.threads_after_release=await threads();
    result.modes[mode]=row;console.log('Indefinite stall passed: '+mode+' '+JSON.stringify(row));
  }
  result.status='passed-indefinite-recording-stall';
}catch(error){result.status='failed';result.error=String(error?.stack||error);await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});throw error;}
finally{result.api_samples=samples.slice(-40);await browser.close();await writeFile(path.join(output,'stall-evidence.json'),JSON.stringify(result,null,2)+'\n');}
