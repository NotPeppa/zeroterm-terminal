// Ten mixed sessions (4 SSH / 3 RDP / 3 VNC, the default global limit) with the bastion-side services held
// in one capped cgroup slice, e.g. 1 CPU / 1 GiB / no swap. Two phases: "interactive" (all ten connected,
// periodic pointer input) and "stress" (three SSH sessions flood output). One quiet SSH session measures
// keystroke echo throughout. A measurement on this host and slice, not a production capacity promise.
// Run it on the fixture host: a slow client link would measure the link, not the server.
// Usage: BASTION_CAPACITY_SLICE=zt1c1g.slice node tests/browser_capacity.mjs <protected-fixture.json> <evidence-directory>
// The slice's cgroup directory is read directly; in a container, bind-mount it read-only and point
// BASTION_CAPACITY_CGROUP at it. BASTION_CAPACITY_NAMES may name a JSON {container id: service} map.
import {selectBrowserTarget} from './browser_targets.mjs';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import path from 'node:path';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_PACKAGE || 'playwright');
const fixture=JSON.parse(await readFile(process.argv[2],'utf8')),output=process.argv[3];
assert.match(fixture.server_id,/^zt-guac-v2-[a-z0-9-]+$/);assert.equal(fixture.capacity_rdp_profiles.length,3);await mkdir(output,{recursive:true});
const SLICE=process.env.BASTION_CAPACITY_SLICE;assert.match(SLICE ?? '',/^[a-z0-9-]+\.slice$/,'BASTION_CAPACITY_SLICE must name the capped slice');
const CGROUP=process.env.BASTION_CAPACITY_CGROUP || '/sys/fs/cgroup/'+SLICE;
const NAMES=process.env.BASTION_CAPACITY_NAMES?JSON.parse(await readFile(process.env.BASTION_CAPACITY_NAMES,'utf8')):{};
const PHASE_MS=Number(process.env.BASTION_CAPACITY_PHASE_MS || 150000);
const FLOOD="while :; do head -c 49152 /dev/urandom | base64; done";
const browser=await chromium.launch({headless:true,args:['--ignore-certificate-errors-spki-list='+fixture.public_spki]});
const result={production_ready:false,capacity_claimed:false,application_image_id:fixture.application_image_id,engine_image_id:fixture.engine_image_id,fixture_server_id:fixture.server_id,slice:SLICE,phase_ms:PHASE_MS,flood_command:FLOOD,phases:{},errors:[]};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function poll(read,accept,timeout=30000){const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await read();if(accept(value))return value;await sleep(200);}throw new Error('capacity poll deadline exceeded');}
async function api(p,resource,body){return p.evaluate(async({resource,body})=>{
  const csrf=document.cookie.split(';').map(row=>row.trim()).find(row=>row.startsWith('bastion_csrf='))?.split('=')[1];
  const send=()=>fetch('/api/v1'+resource,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  let response=await send();
  if(response.status===401){await fetch('/api/v1/auth/refresh',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:'{}'});response=await send();}
  const text=await response.text();return {status:response.status,value:text?JSON.parse(text):null};
},{resource,body});}
async function ok(p,resource,body){const response=await api(p,resource,body);if(response.status<200||response.status>=300)throw new Error('API status '+response.status+' for '+resource);return response.value;}
async function login(p,username=fixture.username){
  await p.goto(fixture.origin,{waitUntil:'networkidle'});
  if(await p.locator('#workspace').isVisible())return;
  await p.locator('#username').fill(username);await p.locator('#password').fill(fixture.password);await p.locator('#login').click();
  await p.locator('#workspace').waitFor({state:'visible'});
}
async function connect(p,profile){
  const response=await selectBrowserTarget(p,profile.asset_id,profile.account_id);assert.equal(response.status(),201);
  const ticket=await response.json();ticket.ws_token='';
  await p.waitForFunction(()=>['目标显示流已就绪','SSH 终端已就绪'].some(text=>document.querySelector('#status').textContent.includes(text)),null,{timeout:60000});
  return ticket.connection_id;
}
const screen=p=>p.evaluate(()=>document.querySelector('.terminal-viewport .xterm-rows')?.textContent ?? '');
async function type(p,text){await p.locator('.terminal-viewport textarea').focus();await p.keyboard.type(text);}
const read=(dir,name)=>readFile(path.join(dir,name),'utf8').then(text=>text.trim());
const kv=text=>Object.fromEntries(text.split('\n').map(line=>line.split(' ')).map(([k,v])=>[k,Number(v)]));
const mib=bytes=>+(Number(bytes)/1048576).toFixed(1);
// The slice's own counters cover every bastion-side container together, which is what a 1c1g host must hold.
async function slice(){
  const cpu=kv(await read(CGROUP,'cpu.stat')),events=kv(await read(CGROUP,'memory.events')),stat=kv(await read(CGROUP,'memory.stat'));
  // Pressure stall information: share of the last 10 s in which some slice task waited for CPU / IO / memory.
  const psi=async name=>Number(/some avg10=([0-9.]+)/.exec(await read(CGROUP,name+'.pressure'))[1]);
  // /proc/meminfo is not namespaced: it shows the whole host, where the browser and target also live.
  const host=kv((await readFile('/proc/meminfo','utf8')).trim().split('\n').map(line=>line.replace(/:\s+/,' ').replace(/ kB$/,'')).join('\n'));
  return {at:Date.now(),memory_mib:mib(await read(CGROUP,'memory.current')),memory_peak_mib:mib(await read(CGROUP,'memory.peak')),
    anon_mib:mib(stat.anon),file_cache_mib:mib(stat.file),swap_mib:mib(await read(CGROUP,'memory.swap.current')),oom_kill:events.oom_kill,
    pids:Number(await read(CGROUP,'pids.current')),cpu_usage_usec:cpu.usage_usec,nr_throttled:cpu.nr_throttled,throttled_usec:cpu.throttled_usec,
    pressure_avg10:{cpu:await psi('cpu'),io:await psi('io'),memory:await psi('memory')},
    host_available_mib:Math.round(host.MemAvailable/1024),host_swap_used_mib:Math.round((host.SwapTotal-host.SwapFree)/1024)};
}
// Per-container memory from each docker-<id>.scope under the slice; anon is what cannot be reclaimed.
async function containers(){
  const scopes=(await readdir(CGROUP)).filter(name=>/^docker-[0-9a-f]{64}\.scope$/.test(name));
  return Promise.all(scopes.map(async scope=>{
    const dir=path.join(CGROUP,scope),id=scope.slice(7,71),stat=kv(await read(dir,'memory.stat'));
    return {name:NAMES[id] ?? id.slice(0,12),memory_mib:mib(await read(dir,'memory.current')),anon_mib:mib(stat.anon),peak_mib:mib(await read(dir,'memory.peak')),pids:Number(await read(dir,'pids.current'))};
  }));
}
const quantile=(values,q)=>{const sorted=[...values].sort((a,b)=>a-b);return sorted[Math.min(sorted.length-1,Math.floor(q*sorted.length))];};
const contexts=[],live=[],RUN=Date.now().toString(36);
try{
  const adminContext=await browser.newContext();contexts.push(adminContext);const admin=await adminContext.newPage();await login(admin);
  assert.equal((await ok(admin,'/info')).server_id,fixture.server_id);
  result.slice_limits={cpu_max:await read(CGROUP,'cpu.max'),memory_max:await read(CGROUP,'memory.max'),swap_max:await read(CGROUP,'memory.swap.max')};
  const before=await slice();result.idle=before;
  const profiles=['ssh','rdp','vnc'].map(protocol=>fixture.profiles.find(row=>row.protocol===protocol));
  // Same layout as the recovery runner: per-user limit 3, four users, 3+3+3+1 = ten; RDP logins differ per user.
  for(let user=0;user<4;user++){
    const username='cap-'+RUN+'-'+user,who=await ok(admin,'/admin/users',{username,password:fixture.password,role:'operator'});
    const userProfiles=[profiles[0],fixture.capacity_rdp_profiles[user%3],profiles[2]];
    for(const profile of userProfiles)await ok(admin,'/admin/grants',{user_id:who.id,asset_id:profile.asset_id,account_id:profile.account_id,expires_at:null});
    const context=await browser.newContext({viewport:{width:1280,height:800}});contexts.push(context);
    for(let index=0;index<(user===3?1:3);index++){
      const p=await context.newPage();p.on('pageerror',error=>result.errors.push(error.message));await login(p,username);
      const profile=userProfiles[(user*3+index)%3];live.push({page:p,profile,user,connection:await connect(p,profile)});
    }
  }
  result.connect_all_ms=Date.now()-before.at;result.after_connect=await slice();
  result.distribution=Object.fromEntries(['ssh','rdp','vnc'].map(protocol=>[protocol,live.filter(item=>item.profile.protocol===protocol).length]));
  assert.deepEqual(result.distribution,{ssh:4,rdp:3,vnc:3});
  const overflow=await api(admin,'/sessions',{asset_id:profiles[0].asset_id,account_id:profiles[0].account_id,display:{width:1280,height:720,dpi:96}});
  assert.equal(overflow.status,429);result.eleventh_rejected=overflow.value.error.code;
  const ssh=live.filter(item=>item.profile.protocol==='ssh'),quiet=ssh.find(item=>item.user===3),floods=ssh.filter(item=>item!==quiet);
  const graphics=live.filter(item=>item.profile.protocol!=='ssh');
  async function echo(phase,index){
    const marker='ZT_CAP_'+phase+'_'+index+'_'+Date.now().toString(36);
    const t0=Date.now();await type(quiet.page,'echo '+marker);
    await poll(()=>screen(quiet.page),text=>text.includes(marker),60000);const keystroke_echo_ms=Date.now()-t0;
    const t1=Date.now();await quiet.page.keyboard.press('Enter');
    await poll(()=>screen(quiet.page),text=>text.split(marker).length>=3,60000);
    const row={keystroke_echo_ms,command_roundtrip_ms:Date.now()-t1};
    await type(quiet.page,'clear');await quiet.page.keyboard.press('Enter');return row;
  }
  async function phase(name){
    const start=await slice(),startedAt=Date.now(),echoes=[],samples=[];let tick=0;
    while(Date.now()-startedAt<PHASE_MS){
      // Real pointer input on every graphical session keeps RDP/VNC repainting and refreshes idle time.
      // A dropped session has no viewport; skip it here so the state sample below records the drop.
      for(const item of graphics){const box=await item.page.locator('.guac-viewport').boundingBox({timeout:2000}).catch(()=>null);if(box)await item.page.mouse.move(box.x+60+(tick%8)*40,box.y+60+(tick%5)*30);}
      echoes.push(await echo(name,tick));
      const sample={at_ms:Date.now()-startedAt,slice:await slice(),containers:await containers(),states:[]};
      for(const item of live)sample.states.push((await ok(admin,'/connections/'+item.connection)).state);
      samples.push(sample);
      const s=sample.slice;console.log(name+' '+JSON.stringify({at_ms:sample.at_ms,mem:s.memory_mib,peak:s.memory_peak_mib,psi:s.pressure_avg10,host_avail:s.host_available_mib,host_swap:s.host_swap_used_mib,echo:echoes.at(-1)}));
      // Keep the samples that led up to a drop: record the phase, then fail.
      if(!sample.states.every(state=>state==='active')){result.phases[name]={dropped_at_ms:sample.at_ms,states:sample.states,samples};throw new Error(name+': a session dropped: '+sample.states.join(','));}
      tick++;await sleep(5000);
    }
    const end=await slice(),elapsed=end.at-start.at;
    result.phases[name]={duration_ms:elapsed,
      cpu_percent_of_one_core:+((end.cpu_usage_usec-start.cpu_usage_usec)/1000/elapsed*100).toFixed(1),
      throttled_periods:end.nr_throttled-start.nr_throttled,throttled_ms:Math.round((end.throttled_usec-start.throttled_usec)/1000),
      memory_peak_mib:end.memory_peak_mib,memory_end_mib:end.memory_mib,swap_mib_max:Math.max(...samples.map(s=>s.slice.swap_mib),end.swap_mib),oom_kill_total:end.oom_kill,
      keystroke_echo_ms:{p50:quantile(echoes.map(e=>e.keystroke_echo_ms),0.5),p95:quantile(echoes.map(e=>e.keystroke_echo_ms),0.95),max:Math.max(...echoes.map(e=>e.keystroke_echo_ms)),n:echoes.length},
      command_roundtrip_ms:{p50:quantile(echoes.map(e=>e.command_roundtrip_ms),0.5),p95:quantile(echoes.map(e=>e.command_roundtrip_ms),0.95),max:Math.max(...echoes.map(e=>e.command_roundtrip_ms))},
      samples};
  }
  await phase('interactive');
  for(const item of floods){await type(item.page,FLOOD);await item.page.keyboard.press('Enter');}
  await phase('stress');
  for(const item of floods){await item.page.locator('.terminal-viewport textarea').focus();await item.page.keyboard.press('Control+c');}
  result.recordings=[];
  for(const item of live){
    await item.page.getByRole('button',{name:'断开',exact:true}).click();
    const row=await poll(async()=>(await ok(admin,'/recordings?connection_id='+item.connection)).items[0],row=>row && ['complete','partial','failed'].includes(row.state),180000);
    result.recordings.push({protocol:item.profile.protocol,state:row.state,bytes:row.bytes});
  }
  result.final=await slice();
  assert(result.recordings.every(row=>row.state==='complete'),'every recording must be complete: '+result.recordings.map(row=>row.state).join(','));
  assert.equal(result.final.oom_kill,0,'the slice must never OOM-kill');
  assert.deepEqual(result.errors,[]);result.status='passed-capacity-measurement';
}catch(error){result.status='failed';result.error=String(error?.stack||error);throw error;}
finally{for(const context of contexts)await context.close().catch(()=>{});await browser.close();await writeFile(path.join(output,'capacity-evidence.json'),JSON.stringify(result,null,2)+'\n');}
