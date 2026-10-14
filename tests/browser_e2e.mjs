import {selectBrowserTarget} from './browser_targets.mjs';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createHash,randomUUID} from 'node:crypto';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
const require=createRequire(import.meta.url), run=promisify(execFile);
const {chromium}=require(process.env.PLAYWRIGHT_PACKAGE || 'playwright');
const fixture=JSON.parse(await readFile(process.argv[2],'utf8'));
assert.match(fixture.server_id,/^zt-guac-v2-[a-z0-9-]+$/);
assert.match(fixture.target_container_id,/^[0-9a-f]{64}$/);
assert.match(fixture.origin,/^https:\/\/localhost:[0-9]+$/);
const output=process.argv[3];await mkdir(output,{recursive:true});
const result=process.env.BASTION_ACCEPTANCE_RESUME_EVIDENCE?JSON.parse(await readFile(process.env.BASTION_ACCEPTANCE_RESUME_EVIDENCE,'utf8')):{production_ready:false,windows_nla_verified:false,native_os_ime_verified:false,fixture_server_id:fixture.server_id,engine_image_id:fixture.engine_image_id,profiles:[],faults:{}};
assert.equal(result.fixture_server_id,fixture.server_id);assert.equal(result.engine_image_id,fixture.engine_image_id);
result.application_image_id=fixture.application_image_id;
const browser=await chromium.launch({headless:true,args:['--ignore-certificate-errors-spki-list='+fixture.public_spki]});
const context=await browser.newContext({viewport:{width:1440,height:1000}});let page=await context.newPage();
result.browser_version=browser.version();result.https_trust='only the independently obtained fixture proxy SPKI is excepted';
const pageErrors=[],socketErrors=[];let sockets=0;
result.unicode_keysyms ??= [];
page.on('pageerror',error=>pageErrors.push(error.message));
page.on('websocket',socket=>{
  sockets++;
  socket.on('framesent',({payload})=>{
    const match=/^3\.key,\d+\.([0-9]+),1\.([01]);$/.exec(Buffer.from(payload).toString());
    if(match && Number(match[1])>=0x01000000)result.unicode_keysyms.push([Number(match[1]),Number(match[2])]);
  });
  socket.on('framereceived',({payload})=>{
    const bytes=Buffer.from(payload);
    if(bytes.length>32768)socketErrors.push('oversized output');
    for(const secret of ['fictional-Guac-pass-123','testpass','-----BEGIN OPENSSH PRIVATE KEY-----'])if(bytes.includes(Buffer.from(secret)))socketErrors.push('target credential in display stream');
  });
});
async function docker(...args){
  if(process.env.BASTION_ACCEPTANCE_SSH_HOST){
    assert(args.every(value=>/^[a-zA-Z0-9_./:=+-]+$/.test(value)),'unsafe fixture command argument');
    return (await run('ssh',['-i',process.env.BASTION_ACCEPTANCE_SSH_KEY,'-p',process.env.BASTION_ACCEPTANCE_SSH_PORT || '22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',process.env.BASTION_ACCEPTANCE_SSH_HOST,'docker '+args.join(' ')],{timeout:15000})).stdout;
  }
  return (await run('docker',args,{timeout:15000})).stdout;
}
async function sql(container,database,text){
  assert.match(container,/^[0-9a-f]{64}$/);assert.match(database,/^zt_guac_v2_[0-9a-f]+$/);
  const args=['exec','-i',container,'psql','-X','-U','bastion','-d',database,'-v','ON_ERROR_STOP=1'];
  const remote=!!process.env.BASTION_ACCEPTANCE_SSH_HOST;
  const command=remote?['-i',process.env.BASTION_ACCEPTANCE_SSH_KEY,'-p',process.env.BASTION_ACCEPTANCE_SSH_PORT || '22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',process.env.BASTION_ACCEPTANCE_SSH_HOST,'docker '+args.join(' ')]:args;
  await new Promise((resolve,reject)=>{
    const child=spawn(remote?'ssh':'docker',command,{stdio:['pipe','ignore','pipe']});let error='';
    child.stderr.on('data',bytes=>{error+=bytes;});child.on('error',reject);child.on('close',code=>code===0?resolve():reject(new Error('fixture SQL failed: '+error)));
    child.stdin.end(text);
  });
}
async function api(resource,body){return page.evaluate(async({resource,body})=>{
  const csrf=document.cookie.split(';').map(value=>value.trim()).find(value=>value.startsWith('bastion_csrf='))?.split('=')[1];
  const response=await fetch('/api/v1'+resource,{credentials:'same-origin',method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  if(!response.ok)throw new Error('fixture API status '+response.status+' for '+resource);
  const text=await response.text();return text?JSON.parse(text):null;
},{resource,body});}
async function poll(read,accept,timeout=15000){
  const deadline=Date.now()+timeout;let value;
  while(Date.now()<deadline){value=await read();if(accept(value))return value;await new Promise(resolve=>setTimeout(resolve,100));}
  throw new Error('fixture poll deadline exceeded');
}
async function select(profile){
  return selectBrowserTarget(page,profile.asset_id,profile.account_id);
}
async function connect(profile){
  const response=await select(profile);assert.equal(response.status(),201);
  const session=await response.json();assert.equal(session.target_protocol,profile.protocol);assert.equal(session.stream_protocol,profile.protocol==='ssh'?'bastion.ssh.v1':'bastion.guac.v1');
  await page.waitForFunction(()=>document.querySelector('#status').textContent.includes('目标显示流已就绪') || document.querySelector('#status').textContent.includes('SSH 终端已就绪'),null,{timeout:50000});
  await poll(()=>api('/connections/'+session.connection_id),row=>row.state==='active');
  await poll(()=>page.locator('.guac-viewport canvas, .terminal-viewport .xterm-screen').count(),value=>value>0);
  if(profile.protocol==='rdp'){
    await page.getByLabel('显示缩放',{exact:true}).selectOption('fit');
    await page.waitForFunction(()=>{
      const viewport=document.querySelector('.guac-viewport, .terminal-viewport'),display=viewport.querySelector(':scope > div');
      if(!display)return false;
      const box=display.getBoundingClientRect();return Math.abs(box.width-viewport.clientWidth)<=1 && Math.abs(box.height-viewport.clientHeight)<=1;
    },null,{timeout:15000});
  }
  return session.connection_id;
}
async function marker(profile,suffix){
  const file='/tmp/ztg-'+randomUUID().replaceAll('-','').slice(0,12)+'-'+suffix[0];
  const display=page.locator('.guac-viewport, .terminal-viewport').first();const box=await display.boundingBox();assert(box);
  await page.mouse.click(box.x+100,box.y+80);
  await page.keyboard.press('Control+c');
  const committed=profile.protocol==='rdp'?'RDP_ASCII_OK':profile.protocol==='vnc'?'中😀':'中文';
  await page.locator('.guac-viewport textarea, .terminal-viewport textarea').evaluate((input,text)=>{
    input.dispatchEvent(new CompositionEvent('compositionstart',{bubbles:true,data:''}));
    input.value=text;
    input.dispatchEvent(new CompositionEvent('compositionend',{bubbles:true,data:text}));
    input.dispatchEvent(new InputEvent('input',{bubbles:true,data:text,isComposing:false,inputType:'insertCompositionText'}));
  },"printf '%s' '"+committed+"' > "+file);
  await new Promise(resolve=>setTimeout(resolve,100));
  await page.keyboard.press('Enter');
  const text=await poll(async()=>{try{return await docker('exec',fixture.target_container_id,'cat',file);}catch{return null;}},value=>value!==null && value!=='');
  assert.equal(text,committed,profile.label+' target Unicode input did not match');
  return true;
}
async function paint(){
  return page.locator('.guac-viewport, .terminal-viewport').first().evaluate(root=>root.classList.contains('terminal-viewport')?root.querySelector('.xterm-rows')?.textContent:[...root.querySelectorAll('canvas')].map(canvas=>canvas.toDataURL()).join('|'));
}
async function recording(connection){return poll(()=>api('/recordings?connection_id='+connection),value=>value.items.length===1).then(value=>value.items[0]);}
try{
  await page.goto(fixture.origin,{waitUntil:'networkidle'});
  const info=await api('/info');assert.equal(info.server_id,fixture.server_id);assert.equal(info.production_ready,false);
  await page.locator('#username').fill(fixture.username);await page.locator('#password').fill(fixture.password);await page.locator('#login').click();
  await page.locator('#workspace').waitFor({state:'visible'});
  for(const profile of fixture.profiles.filter(profile=>!result.profiles.some(row=>row.label===profile.label && row.offline_verified_replay))){
    const connection=await connect(profile),row={label:profile.label,protocol:profile.protocol,connection_id:connection};
    const before=await paint();row.keyboard_target_roundtrip=await marker(profile,'first');row.unicode_input=profile.protocol!=='rdp';row.non_bmp_input_supported=profile.protocol==='vnc';if(profile.protocol==='rdp')row.target_input_limit='xrdp TLS fixture ignores Unicode keyboard events; Windows NLA/IME not verified';
    await poll(paint,value=>value!==before);
    if(profile.protocol==='ssh')await page.getByLabel('终端字号',{exact:true}).selectOption('18');else await page.getByLabel('显示缩放',{exact:true}).selectOption('0.5');row.scaled_mouse_input=await marker(profile,'scaled');
    const input=page.locator('.guac-viewport textarea, .terminal-viewport textarea');await input.focus();await page.keyboard.down('Shift');await page.getByLabel(profile.protocol==='ssh'?'终端字号':'显示缩放',{exact:true}).focus();await page.keyboard.up('Shift');
    row.focus_release=true;
    await page.getByRole('button',{name:'全屏',exact:true}).click();await page.waitForFunction(()=>!!document.fullscreenElement);
    await page.getByRole('button',{name:'全屏',exact:true}).click();await page.waitForFunction(()=>!document.fullscreenElement);row.fullscreen=true;
    for(const size of [{width:1920,height:1080},{width:800,height:600},{width:1440,height:1000}]){
      await page.setViewportSize(size);await page.waitForTimeout(200);
      const edge=await page.locator('.guac-viewport > div, .terminal-viewport > div').first().boundingBox();assert(edge);
      await page.mouse.click(edge.x+1,edge.y+1);
      await page.mouse.move(edge.x+edge.width-0.1,edge.y+1);
      await page.mouse.move(edge.x+1,edge.y+edge.height-0.1);
    }
    assert.equal((await api('/connections/'+connection)).state,'active','resize and edge movement closed the connection');row.resize_edge_input=true;
    await page.screenshot({path:path.join(output,profile.label+'-live.png')});
    row.canvas_sha256=createHash('sha256').update(await paint()).digest('hex');
    await page.getByRole('button',{name:'断开',exact:true}).click();await poll(()=>api('/connections/'+connection),value=>value.state==='closed');
    const rec=await poll(()=>recording(connection),value=>value.state==='complete');row.recording_id=rec.id;
    const count=sockets;await page.evaluate(id=>{location.hash='#/recordings/'+id;},connection);
    await page.getByLabel('录制 ID',{exact:true}).fill(rec.id);await page.getByRole('button',{name:'播放 / 从头重播',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('#status').textContent==='只读回放完成。',null,{timeout:60000});
    assert.equal(sockets,count,'offline replay opened a target WebSocket');row.offline_verified_replay=true;
    await page.screenshot({path:path.join(output,profile.label+'-replay.png')});result.profiles.push(row);
    await page.evaluate(()=>{location.hash='#/assets';});
  }
  if(!result.mixed_protocol_smoke){const primary=page,mixed=[];
  try{
    for(const protocol of ['ssh','rdp','vnc']){
      const profile=fixture.profiles.find(row=>row.protocol===protocol);page=await context.newPage();
      await page.goto(fixture.origin,{waitUntil:'networkidle'});await page.locator('#workspace').waitFor({state:'visible'});
      mixed.push({profile,page,connection:await connect(profile)});
    }
    const overflow=await page.evaluate(async profile=>{
      const csrf=document.cookie.split(';').map(value=>value.trim()).find(value=>value.startsWith('bastion_csrf='))?.split('=')[1];
      const response=await fetch('/api/v1/sessions',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Bastion-CSRF':csrf},body:JSON.stringify({asset_id:profile.asset_id,account_id:profile.account_id,display:{width:1280,height:720,dpi:96}})});
      return {status:response.status,body:await response.json()};
    },fixture.profiles[0]);assert.equal(overflow.status,429);assert.equal(overflow.body.error.code,'CONNECTION_LIMIT');
    for(const item of mixed){page=item.page;await marker(item.profile,'mixed');}
    const ids=(await docker('ps','--no-trunc','-q','--filter','label=com.docker.compose.project='+fixture.server_id)).trim().split(/\s+/);
    assert(ids.every(id=>/^[0-9a-f]{64}$/.test(id)));
    const resources=(await docker('stats','--no-stream','--format','json',...ids)).trim().split('\n').map(line=>JSON.parse(line));
    result.mixed_protocol_smoke={active_connections:3,protocols:['ssh','rdp','vnc'],fourth_user_connection_rejected:true,resources,capacity_acceptance_claimed:false};
  }finally{
    for(const item of mixed){page=item.page;await page.getByRole('button',{name:'断开',exact:true}).click().catch(()=>{});await poll(()=>api('/connections/'+item.connection),row=>!['active','connecting','closing'].includes(row.state)).catch(()=>{});await item.page.close();}
    page=primary;
  }
  }
  const profile=fixture.profiles[0];let connection=await connect(profile);
  const started=Date.now();await api('/connections/'+connection+'/disconnect',{});
  await poll(()=>api('/connections/'+connection),value=>!['connecting','active','closing'].includes(value.state));
  const revoked=await poll(()=>recording(connection),row=>!['preparing','active'].includes(row.state));
  result.faults.revocation={closed_ms:Date.now()-started,recording_state:revoked.state};
  assert(['partial','failed'].includes(revoked.state));
  await page.evaluate(()=>{location.hash='#/assets';});await page.evaluate(()=>{location.hash='#/assets';});
  connection=await connect(profile);
  const container=await docker('ps','--no-trunc','-q','--filter','label=com.docker.compose.project='+fixture.server_id,'--filter','label=com.docker.compose.service=bastion');
  assert.match(container.trim(),/^[0-9a-f]{64}$/);
  await docker('exec',container.trim(),'chmod','0500','/var/lib/zeroterm-bastion/recordings');
  try{
    const unavailable=await api('/info');assert.equal(unavailable.recording.available,false);
    await page.locator('.guac-viewport textarea, .terminal-viewport textarea').focus();await page.keyboard.type('echo recording-fault');await page.keyboard.press('Enter');
    await poll(()=>api('/connections/'+connection),value=>!['connecting','active','closing'].includes(value.state));
    const state=await poll(()=>recording(connection),value=>!['preparing','active'].includes(value.state));
    assert.notEqual(state.state,'complete');result.faults.recording_permission={closed:true,recording_state:state.state};
  }finally{await docker('exec',container.trim(),'chmod','0700','/var/lib/zeroterm-bastion/recordings');}
  await page.evaluate(()=>{location.hash='#/assets';});await page.evaluate(()=>{location.hash='#/assets';});
  connection=await connect(profile);
  // Keep the real target producing output; an idle, fully synced stream needs no checkpoint.
  await page.locator('.guac-viewport textarea, .terminal-viewport textarea').focus();await page.keyboard.type('while true; do echo recording-checkpoint; sleep 0.2; done');await page.keyboard.press('Enter');
  const restored=(await docker('ps','--no-trunc','-q','--filter','label=zeroterm.acceptance='+fixture.server_id)).trim();
  const pg=restored || (await docker('ps','--no-trunc','-q','--filter','label=com.docker.compose.project='+fixture.server_id,'--filter','label=com.docker.compose.service=postgres')).trim();
  assert.match(pg,/^[0-9a-f]{64}$/);
  const database=(await docker('exec',pg,'printenv','POSTGRES_DB')).trim();
  await sql(pg,database,"CREATE FUNCTION zt_fixture_fail_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.state='active' AND NEW.last_written_seq>OLD.last_written_seq THEN RAISE EXCEPTION 'controlled checkpoint failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER zt_fixture_fail_checkpoint BEFORE UPDATE OF last_written_seq,last_synced_seq ON recordings FOR EACH ROW EXECUTE FUNCTION zt_fixture_fail_checkpoint();");
  try{
    await poll(()=>api('/connections/'+connection),row=>!['connecting','active','closing'].includes(row.state),20000);
    const failed=await poll(()=>recording(connection),row=>!['preparing','active'].includes(row.state));
    assert(['partial','failed'].includes(failed.state));result.faults.periodic_checkpoint={closed_without_further_user_input:true,autonomous_target_output:true,recording_state:failed.state};
  }finally{await sql(pg,database,'DROP TRIGGER zt_fixture_fail_checkpoint ON recordings; DROP FUNCTION zt_fixture_fail_checkpoint();');}
  const daemon=(await docker('ps','--no-trunc','-q','--filter','label=com.docker.compose.project='+fixture.server_id,'--filter','label=com.docker.compose.service=guacd')).trim();
  assert.match(daemon,/^[0-9a-f]{64}$/);await docker('stop',daemon);
  try{
    // SSH runs through the Rust SSH/PTY path (docs/ssh-xterm.md); only RDP/VNC depend on guacd.
    const down=await api('/info');assert(!down.features.web_rdp && !down.features.web_vnc);assert(down.features.web_ssh,'SSH must not depend on guacd');assert.equal((await api('/me')).user.username,fixture.username);
    result.faults.guacd_outage={rdp_vnc_unavailable:true,ssh_still_available:true,management_authenticated:true,replay_available:down.features.recording_replay};
  }finally{await docker('start',daemon);await poll(()=>api('/info'),info=>info.features.web_ssh && info.features.web_rdp && info.features.web_vnc);}
  assert.deepEqual(socketErrors,[]);assert.deepEqual(pageErrors,[]);delete result.error;result.status='passed-real-browser-component';
}catch(error){result.status='failed';result.error=error.message;await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});throw error;}
finally{await browser.close();await writeFile(path.join(output,'browser-evidence.json'),JSON.stringify(result,null,2)+'\n');}
console.log(JSON.stringify(result,null,2));
