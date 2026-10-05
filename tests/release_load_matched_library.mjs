// Isolated release load: native Node24 TLS/WSS, no tokens in URLs/logs,
// 32KiB file streaming, bounded terminal observation, and full-hour shell pulses.
import {readFile,writeFile} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {request as httpsRequest} from 'node:https';
import {pipeline} from 'node:stream/promises';
import assert from 'node:assert/strict';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const quantiles=values=>{const sorted=[...values].sort((a,b)=>a-b);return {count:sorted.length,p50:sorted[Math.ceil(sorted.length*.5)-1]??null,p95:sorted[Math.ceil(sorted.length*.95)-1]??null,max:sorted.at(-1)??null};};
if(process.argv.includes('--selftest')){assert.deepEqual(quantiles([3,1,2]),{count:3,p50:2,p95:3,max:3});console.log('release-load local statistics check passed');process.exit(0);}
const f=JSON.parse(await readFile(process.env.BASTION_RELEASE_LOAD_FIXTURE,'utf8'));
const base=f.api_url;
const started=Date.now();
const report={source_archive_sha256:f.source_archive_sha256,runner_sha256:f.runner_sha256,binary_sha256:f.binary_sha256,build_profile:f.build_profile,content_transport:'native https 32KiB stream, small JSON fetch',preflight:f.preflight,started_at:new Date().toISOString(),duration_required_seconds:f.seconds,phase:'initializing',echo_ms:[],pulse_ms:[],files:[],revocations:[],errors:[]};
const save=async()=>writeFile(`${f.workdir}/result.json`,JSON.stringify({...report,echo:quantiles(report.echo_ms),pulse:quantiles(report.pulse_ms)},null,2)+'\n',{mode:0o600});
class Browser{
  constructor(username){this.username=username;this.cookies=new Map();this.csrf='';}
  headers(){return {Origin:base,Cookie:[...this.cookies].map(([name,value])=>`${name}=${value}`).join('; ')};}
  async request(path,{method='GET',json,body,status=200,timeout=120000}={}){
    const headers=this.headers();if(method!=='GET')headers['X-Bastion-CSRF']=this.csrf;
    if(json!==undefined){headers['Content-Type']='application/json';body=JSON.stringify(json);}
    if(body!==undefined&&json===undefined)headers['Content-Type']='application/octet-stream';
    const response=await fetch(`${base}/api/v1${path}`,{method,headers,body,duplex:body&&typeof body!=='string'?'half':undefined,redirect:'manual',signal:AbortSignal.timeout(timeout)});
    for(const raw of response.headers.getSetCookie()){
      const [pair]=raw.split(';');const split=pair.indexOf('=');const name=pair.slice(0,split),value=pair.slice(split+1);
      assert(raw.includes('Secure'));assert(raw.includes('SameSite=Strict'));if(name!=='bastion_csrf')assert(raw.includes('HttpOnly'));
      if(value)this.cookies.set(name,value);else this.cookies.delete(name);
    }
    if(response.status!==status)throw new Error(`HTTP ${method} expected${status} got${response.status}`);
    assert.equal(response.headers.get('cache-control'),'no-store');return response;
  }
  async json(path,options){const response=await this.request(path,options);return response.status===204?null:response.json();}
  async login(){this.csrf=(await this.json('/auth/csrf')).csrf_token;const result=await this.json('/auth/login',{method:'POST',json:{username:this.username,password:f.password,device_label:'owned release load',client_type:'web'}});assert(!('access_token' in result));assert(!('refresh_token' in result));}
}
class Lane{
  constructor(ws){this.ws=ws;ws.binaryType='arraybuffer';this.controls=[];this.controlWaiters=[];this.outputWaiters=[];this.rolling='';this.bytes=0;this.closed=false;this.closedAt=null;this.error=null;
    this.closedPromise=new Promise(resolve=>{this.closeResolve=resolve;});
    ws.addEventListener('message',event=>{
      if(typeof event.data==='string'){
        const frame=JSON.parse(event.data);if(frame.type==='error'){this.error=frame.code;this.reject(new Error(`channel error ${frame.code}`));return;}
        const index=this.controlWaiters.findIndex(waiter=>waiter.type===frame.type&&(!waiter.id||waiter.id===frame.channel_id));
        if(index>=0){this.controlWaiters.splice(index,1)[0].resolve(frame);}else{if(this.controls.length>=16){this.error='control queue overflow';this.ws.close();return;}this.controls.push(frame);}
      }else{
        const data=new Uint8Array(event.data);assert(data.length>=6);assert(data.length<=32774);this.bytes+=data.length-6;
        this.rolling=(this.rolling+Buffer.from(data.subarray(6)).toString('utf8')).slice(-16384);
        for(const waiter of [...this.outputWaiters])if(this.rolling.includes(waiter.marker)){this.outputWaiters.splice(this.outputWaiters.indexOf(waiter),1);waiter.resolve();}
      }
    });
    ws.addEventListener('close',()=>{this.closed=true;this.closedAt=performance.now();this.closeResolve();this.reject(new Error('WSS closed'));});
    ws.addEventListener('error',()=>{this.error='WSS transport error';this.reject(new Error(this.error));});
  }
  reject(error){for(const waiter of [...this.controlWaiters,...this.outputWaiters])waiter.reject(error);this.controlWaiters=[];this.outputWaiters=[];}
  expect(type,id,deadline=30000){const index=this.controls.findIndex(frame=>frame.type===type&&(!id||frame.channel_id===id));if(index>=0)return Promise.resolve(this.controls.splice(index,1)[0]);return this.wait(this.controlWaiters,{type,id},deadline);}
  waitOutput(marker,deadline=30000){if(this.rolling.includes(marker))return Promise.resolve();return this.wait(this.outputWaiters,{marker},deadline);}
  wait(list,fields,deadline){if(this.closed)return Promise.reject(new Error('WSS already closed'));return new Promise((resolve,reject)=>{const waiter={...fields,resolve:value=>{clearTimeout(timer);resolve(value);},reject:error=>{clearTimeout(timer);reject(error);}};const timer=setTimeout(()=>{const index=list.indexOf(waiter);if(index>=0)list.splice(index,1);reject(new Error('target acknowledgement deadline'));},deadline);list.push(waiter);});}
  control(type,id,extra={}){this.ws.send(JSON.stringify({v:1,type,...(id?{channel_id:id}:{}),...extra}));}
  input(bytes){const data=Buffer.from(bytes);assert(data.length<=32768);const frame=Buffer.alloc(data.length+6);frame[0]=1;frame[1]=1;frame.writeUInt32BE(1,2);data.copy(frame,6);this.ws.send(frame);}
}
async function connect(browser,caps){
  const ticket=await browser.json('/sessions',{method:'POST',status:201,json:{...f.asset,capabilities:caps,purpose:caps[0]==='sftp'?'sftp':'terminal'}});
  const ws=new WebSocket(base.replace(/^https:/,'wss:')+`/api/v1/sessions/${ticket.session_id}/stream`,{protocols:['bastion.v1',ticket.ws_token],headers:browser.headers()});
  const lane=new Lane(ws);lane.connection=ticket.connection_id;lane.browser=browser;
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('WSS handshake deadline')),30000);ws.addEventListener('open',()=>{clearTimeout(timer);resolve();},{once:true});ws.addEventListener('error',()=>{clearTimeout(timer);reject(new Error('WSS handshake failed'));},{once:true});});
  await lane.expect('session_ready');return lane;
}
async function pulse(lane,index,sequence){
  const marker=`LOAD-PULSE-${index}-${sequence}-${f.target_id}-DONE`;
  lane.rolling='';const ack=lane.waitOutput(marker);const before=performance.now();
  lane.input(`\x15printf '\\nLOAD-PULSE-${index}-${sequence}-%s-DONE\\n' "$BASTION_TARGET_ID"\n`);await ack;
  report.pulse_ms.push(performance.now()-before);
}
async function echo(lane,index,sequence){
  const marker='|';lane.rolling='';const ack=lane.waitOutput(marker);const before=performance.now();lane.input(marker);await ack;report.echo_ms.push(performance.now()-before);lane.input('\x15');
}
async function openShell(browser,index){
  const lane=await connect(browser,['shell']);lane.index=index;
  lane.control('open',1,{kind:'shell'});await lane.expect('opened',1);
  lane.control('pty',1,{term:'xterm',cols:80,rows:24});await lane.expect('pty_ready',1);
  lane.control('shell',1);await lane.expect('ready',1);await pulse(lane,index,0);return lane;
}
async function closeShell(lane){
  lane.input('\x15exit 0\n');await lane.expect('closed',1);lane.ws.close();await lane.closedPromise;
  for(let attempt=0;attempt<40;attempt++){
    const channels=await lane.browser.json(`/connections/${lane.connection}/channels`);const channel=channels.items.find(item=>item.kind==='shell');
    if(channel?.recording_id){const recording=await lane.browser.json(`/recordings/${channel.recording_id}`);if(recording.state==='complete'){assert.equal(recording.last_written_seq,recording.last_synced_seq);return {connection_id:lane.connection,recording_id:recording.id,bytes:lane.bytes};}if(['failed','corrupt','missing'].includes(recording.state))throw new Error('required recording failed');}
    await sleep(250);
  }
  throw new Error('required recording complete/checkpoint deadline');
}
function content(browser,path,{file}={}){
  const method=file?'PUT':'GET',status=file?201:200;
  const headers=browser.headers();if(file)Object.assign(headers,{'X-Bastion-CSRF':browser.csrf,'Content-Type':'application/octet-stream','Content-Length':String(file.size)});
  return new Promise((resolve,reject)=>{
    let input,timer,settled=false;
    const req=httpsRequest(`${base}/api/v1${path}`,{method,headers,highWaterMark:32768},response=>{
      (async()=>{
        if(response.statusCode!==status)throw new Error(`content ${method} expected${status} got${response.statusCode}`);
        assert.equal(response.headers['cache-control'],'no-store');assert(response.headers['x-request-id']);
        const hash=createHash('sha256'),small=[];let bytes=0;
        for await(const chunk of response){bytes+=chunk.length;if(file){if(bytes>8192)throw new Error('upload response too large');small.push(chunk);}else hash.update(chunk);}
        finish(null,file?JSON.parse(Buffer.concat(small).toString('utf8')):{bytes,sha256:hash.digest('hex')});
      })().catch(error=>{response.destroy();finish(error);});
    });
    function finish(error,value){if(settled)return;settled=true;clearTimeout(timer);if(error){input?.destroy();req.destroy();reject(error);}else resolve(value);}
    timer=setTimeout(()=>finish(new Error('content absolute deadline')),1800000);
    req.setTimeout(30000,()=>finish(new Error('content stalled')));req.on('error',finish);
    if(file){input=createReadStream(file.local,{highWaterMark:32768});pipeline(input,req).catch(finish);}else req.end();
  });
}
async function transfer(browser,file,index){
  const lane=await connect(browser,['sftp']);const path=`/connections/${lane.connection}/files/content?path=${encodeURIComponent(file.remote)}`;
  try{
    const began=performance.now();const uploaded=await content(browser,path,{file});
    const uploadedAt=performance.now();assert.equal(uploaded.bytes,file.size);
    const download=await content(browser,path);const done=performance.now();assert.equal(download.bytes,file.size);assert.equal(download.sha256,file.sha256);
    await browser.request(`/connections/${lane.connection}/files/operations`,{method:'POST',status:204,json:{operation:'remove',path:file.remote}});
    return {upload_started_ms:began,upload_finished_ms:uploadedAt,download_started_ms:uploadedAt,download_finished_ms:done,index,bytes:file.size,sha256:file.sha256,upload_seconds:(uploadedAt-began)/1000,download_seconds:(done-uploadedAt)/1000,upload_bytes_per_second:file.size*1000/(uploadedAt-began),download_bytes_per_second:file.size*1000/(done-uploadedAt)};
  }finally{lane.ws.close();await lane.closedPromise;}
}
async function revokeProbe(browser,index){
  const lane=await openShell(browser,100+index);
  try{const devices=await browser.json('/me/sessions');const current=devices.items.find(item=>item.current);assert(current);
  const start=performance.now();await browser.request(`/me/sessions/${current.id}`,{method:'DELETE',status:204});
  await Promise.race([lane.closedPromise,sleep(3000).then(()=>{throw new Error('device revoke exceeded3s');})]);const duration=lane.closedAt-start;assert(duration<=3000);return duration;
  }finally{if(!lane.closed)lane.ws.close();}
}
export {Browser,revokeProbe,quantiles,transfer};
if(!process.env.BASTION_RELEASE_LOAD_LIBRARY){
const lanes=[];
try{
  const browsers=f.users.map(username=>new Browser(username));const loginStarted=performance.now();for(const browser of browsers.slice(0,8))await browser.login();
  const info=await browsers[0].json('/info');assert.equal(info.production_ready,false);assert.equal(info.recording.required,true);assert.equal(info.recording.available,true);assert.equal(info.features.copy_jobs,false);
  const total=f.preflight?3:70;
  for(let index=0;index<total;index++){const user=index<50?Math.floor(index/10):5+Math.floor((index-50)/10);lanes.push(await openShell(browsers[user],index));}
  report.phase='holding';report.active_shells=f.preflight?3:50;report.mixed_terminals=f.preflight?0:20;report.hold_started_at=new Date().toISOString();await save();
  const holdStarted=performance.now(),deadline=holdStarted+f.seconds*1000;
  let sequence=0,stopPulses=false,lastRefresh=performance.now();
  const pulses=(async()=>{while(!stopPulses){if(performance.now()-lastRefresh>=300000){for(const browser of browsers.slice(0,8))await browser.json('/auth/refresh',{method:'POST',json:{}});lastRefresh=performance.now();}for(const lane of lanes){if(lane.closed||lane.error)throw new Error('active terminal unexpectedly closed');await echo(lane,lane.index,sequence);await pulse(lane,lane.index,++sequence);}await save();await sleep(f.preflight?1000:30000);}})();
  const transferPromise=Promise.all(f.files.map((file,index)=>transfer(browsers[7],file,index))).then(results=>{report.files=results;return save();});
  await Promise.race([sleep(f.seconds*1000),pulses,transferPromise.then(()=>new Promise(()=>{}))]);assert(performance.now()>=deadline-10,'one-hour hold was not completed');
  await transferPromise;stopPulses=true;await pulses;
  report.hold_seconds=(performance.now()-holdStarted)/1000;report.phase='finalizing';await save();
  report.recordings=[];for(const lane of lanes)report.recordings.push(await closeShell(lane));
  report.phase='revocation';await save();await sleep(Math.max(0,65000-(performance.now()-loginStarted)));for(let index=8;index<13;index++){await browsers[index].login();report.revocations.push(await revokeProbe(browsers[index],index));}
  report.revoke_ms=quantiles(report.revocations);
  const sums=direction=>report.files.reduce((total,file)=>total+file[`${direction}_bytes_per_second`],0);
  report.direct_baseline=f.baseline;report.proxy_aggregate_ratio={upload:sums('upload')/f.baseline.upload.bytes_per_second,download:sums('download')/f.baseline.download.bytes_per_second};
  report.throughput_target_met=report.proxy_aggregate_ratio.upload>=.7&&report.proxy_aggregate_ratio.download>=.7;
  report.phase='completed';report.finished_at=new Date().toISOString();report.elapsed_seconds=(Date.now()-started)/1000;await save();
  console.log(JSON.stringify({phase:'completed',preflight:f.preflight,hold_seconds:report.hold_seconds,required_recordings:report.recordings.length,revocation:report.revoke_ms,throughput_target_met:report.throughput_target_met}));
}catch(error){report.phase='failed';report.errors.push({name:error.name,message:error.message});await save();console.error('Owned load client failed; no release acceptance claimed');process.exitCode=1;}
finally{for(const lane of lanes)if(!lane.closed)lane.ws.close();}
}
