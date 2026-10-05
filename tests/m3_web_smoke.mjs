// Real HTTPS/WSS candidate acceptance. Fixture secrets are read from a 0600 file,
// never argv/logs. NODE_EXTRA_CA_CERTS must trust the isolated fixture CA.
import { readFile } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const f = JSON.parse(await readFile(process.env.BASTION_M3_FIXTURE, 'utf8'));
const base = f.api_url;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
class Browser {
  cookies = new Map(); csrf = '';
  async request(path, {method='GET', json, bytes, status=200}={}) {
    const headers = {Origin: base, Cookie: [...this.cookies].map(([k,v])=>`${k}=${v}`).join('; ')};
    if (!['GET','HEAD'].includes(method)) headers['X-Bastion-CSRF'] = this.csrf;
    let body;
    if (json !== undefined) {headers['Content-Type']='application/json';body=JSON.stringify(json);}
    if (bytes !== undefined) {headers['Content-Type']='application/octet-stream';body=bytes;}
    const response = await fetch(base+'/api/v1'+path, {method, headers, body, redirect:'manual', signal:AbortSignal.timeout(30000)});
    for (const raw of response.headers.getSetCookie()) {
      const [name,value] = raw.split(';')[0].split('=');
      assert(raw.includes('SameSite=Strict'));
      assert(raw.includes('Secure'));
      if (name !== 'bastion_csrf') assert(raw.includes('HttpOnly'));
      if (value) this.cookies.set(name,value); else this.cookies.delete(name);
    }
    assert.equal(response.status,status,`unexpected status: ${method} ${path} (request_id ${response.headers.get('x-request-id')})`);
    assert.equal(response.headers.get('cache-control'),'no-store');
    assert(response.headers.get('x-request-id'));
    return response;
  }
  async json(path, options) {const r=await this.request(path,options);return r.status===204?null:r.json();}
  async login(username=f.username) {
    this.csrf=(await this.json('/auth/csrf')).csrf_token;
    const result=await this.json('/auth/login',{method:'POST',json:{username,password:f.password,device_label:'M3 HTTPS integration',client_type:'web'}});
    assert(!('access_token' in result));assert(!('refresh_token' in result));
  }
}
class Lane {
  frames=[]; readers=[]; closed=false;
  constructor(ws) {
    this.ws=ws;ws.binaryType='arraybuffer';
    ws.addEventListener('message',event=>{
      const frame=typeof event.data==='string'?JSON.parse(event.data):new Uint8Array(event.data);
      const waiter=this.readers.shift();if(waiter)waiter.resolve(frame);else this.frames.push(frame);
    });
    const end=()=>{this.closed=true;for(const r of this.readers.splice(0))r.reject(new Error('WSS ended before expected frame'));};
    ws.addEventListener('close',end);ws.addEventListener('error',end);
  }
  next() {
    if(this.frames.length)return Promise.resolve(this.frames.shift());
    if(this.closed)return Promise.reject(new Error('WSS closed'));
    return new Promise((resolve,reject)=>{
      const item={resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}};
      const timer=setTimeout(()=>{const i=this.readers.indexOf(item);if(i>=0)this.readers.splice(i,1);reject(new Error('WSS frame deadline'));},15000);
      this.readers.push(item);
    });
  }
  control(type,channel_id,extra={}) {this.ws.send(JSON.stringify({v:1,type,...(channel_id?{channel_id}:{}),...extra}));}
  input(channel_id,bytes) {const frame=Buffer.alloc(6+bytes.length);frame[0]=1;frame[1]=1;frame.writeUInt32BE(channel_id,2);Buffer.from(bytes).copy(frame,6);this.ws.send(frame);}
  async expect(type,id) {const frame=await this.next();assert.equal(frame.type,type);if(id)assert.equal(frame.channel_id,id);return frame;}
  close(){this.ws.close();}
}
// Native Node WebSocket supports WebSocketInit headers for this synthetic client.
// A real browser still supplies Cookie/Origin itself; never place them in a URL.
async function connect(browser,asset,caps) {
  const ticket=await browser.json('/sessions',{method:'POST',status:201,json:{asset_id:asset.asset_id,account_id:asset.account_id,capabilities:caps,purpose:caps[0]==='sftp'?'sftp':'terminal'}});
  const ws=new WebSocket(base.replace(/^https:/,'wss:')+`/api/v1/sessions/${ticket.session_id}/stream`,{
    protocols:['bastion.v1',ticket.ws_token],
    headers:{Origin:base,Cookie:[...browser.cookies].map(([k,v])=>`${k}=${v}`).join('; ')},
  });
  const lane=new Lane(ws);await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',()=>reject(new Error('WSS handshake failed')),{once:true});});
  await lane.expect('session_ready');
  return {lane,connection_id:ticket.connection_id};
}

const browser=new Browser();await browser.login();
const info=await browser.json('/info');
assert.equal(info.production_ready,false);assert.equal(info.recording.required,true);assert.equal(info.recording.available,true);
assert.equal(info.features.copy_jobs,false);
const asset=f.assets[0];
const {lane,connection_id}=await connect(browser,asset,['shell','exec','sftp']);
try {
  lane.control('open',1,{kind:'shell'});await lane.expect('opened',1);
  lane.control('pty',1,{term:'xterm-256color',cols:80,rows:24});await lane.expect('pty_ready',1);
  lane.control('shell',1);await lane.expect('ready',1);
  lane.input(1,Buffer.from("printf '\\nM3-SHELL-%s\\n' \"$BASTION_TARGET_ID\"; exit 7\n"));
  let shell=Buffer.alloc(0),exited=false,closed=false;
  while(!closed){const frame=await lane.next();if(frame instanceof Uint8Array){assert.equal(new DataView(frame.buffer,frame.byteOffset).getUint32(2),1);shell=Buffer.concat([shell,frame.subarray(6)]);}else if(frame.type==='exit'){assert.equal(frame.exit_code,7);exited=true;}else if(frame.type==='closed')closed=true;else assert.notEqual(frame.type,'error');}
  assert(exited);assert(shell.includes(Buffer.from('M3-SHELL-A')));

  assert(f.assets.length>=2,'two independent target fixtures required');
  const second=await connect(browser,f.assets[1],['exec']);
  try {
    second.lane.control('open',1,{kind:'exec'});await second.lane.expect('opened',1);
    second.lane.control('exec_start',1,{command_base64:Buffer.from('printf "M3-TARGET-%s" "$BASTION_TARGET_ID"').toString('base64')});
    await second.lane.expect('ready',1);second.lane.control('eof',1);
    const targetOutput=[];let targetClosed=false;
    while(!targetClosed){const frame=await second.lane.next();if(frame instanceof Uint8Array){assert.equal(frame[1],2);targetOutput.push(frame.subarray(6));}else if(frame.type==='exit')assert.equal(frame.exit_code,0);else if(frame.type==='closed')targetClosed=true;else assert.notEqual(frame.type,'error');}
    assert.equal(Buffer.concat(targetOutput).toString(),'M3-TARGET-B');
  } finally {second.lane.close();}

  lane.control('open',2,{kind:'exec'});await lane.expect('opened',2);
  lane.control('exec_start',2,{command_base64:Buffer.from("printf '\\377\\000'; printf 'm3-stderr' >&2; exit 7").toString('base64')});
  await lane.expect('ready',2);const streams={2:[],3:[]};let execClosed=false;
  while(!execClosed){const frame=await lane.next();if(frame instanceof Uint8Array){assert.equal(new DataView(frame.buffer,frame.byteOffset).getUint32(2),2);assert(frame[1]===2||frame[1]===3);streams[frame[1]].push(frame.subarray(6));}else if(frame.type==='exit')assert.equal(frame.exit_code,7);else if(frame.type==='closed')execClosed=true;else assert.notEqual(frame.type,'error');}
  assert.deepEqual(Buffer.concat(streams[2]),Buffer.from([255,0]));assert.equal(Buffer.concat(streams[3]).toString(),'m3-stderr');

  const remote=f.remote_file;
  const data=randomBytes(1024*1024);
  const uploaded=await browser.json(`/connections/${connection_id}/files/content?path=${encodeURIComponent(remote)}`,{method:'PUT',bytes:data,status:201});
  assert.equal(uploaded.bytes,data.length);
  const download=await browser.request(`/connections/${connection_id}/files/content?path=${encodeURIComponent(remote)}`);
  assert(download.headers.get('content-disposition')?.startsWith('attachment;'));
  assert.equal(digest(Buffer.from(await download.arrayBuffer())),digest(data));
  const differentLogin=new Browser();await differentLogin.login();
  await differentLogin.request(`/connections/${connection_id}/files?path=${encodeURIComponent(remote)}&operation=stat`,{status:403});
  await browser.request(`/connections/${connection_id}/files/operations`,{method:'POST',json:{operation:'remove',path:remote},status:204});

  let recording;
  for(let attempt=0;attempt<20;attempt++){
    const channels=await browser.json(`/connections/${connection_id}/channels`);
    const shellChannel=channels.items.find(x=>x.kind==='shell');
    if(shellChannel?.recording_id){recording=await browser.json(`/recordings/${shellChannel.recording_id}`);if(recording.state==='complete')break;}
    await delay(250);
  }
  assert.equal(recording?.state,'complete');assert.equal(recording.last_written_seq,recording.last_synced_seq);
  const replay=(await browser.request(`/recordings/${recording.id}/content`)).body.getReader();
  let text='';const decoder=new TextDecoder();while(true){const chunk=await replay.read();if(chunk.done)break;text+=decoder.decode(chunk.value,{stream:true});}text+=decoder.decode();
  const events=text.trimEnd().split('\n').map(x=>JSON.parse(x));assert.equal(events[0].type,'meta');assert.equal(events.at(-1).type,'end');
  events.forEach((event,index)=>assert.equal(event.seq,index));assert(events.some(x=>x.type==='exit'&&x.exit_code===7));
  assert.equal(info.features.web_exec,true);assert.equal(info.features.web_sftp,true);
  const devices=await browser.json('/me/sessions');const current=devices.items.find(x=>x.current);assert(current);
  const socketClosed=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('device revoke did not close WSS within 3 seconds')),3000);lane.ws.addEventListener('close',()=>{clearTimeout(timer);resolve();},{once:true});});
  await browser.request(`/me/sessions/${current.id}`,{method:'DELETE',status:204});await socketClosed;
  console.log('M3 HTTPS/WSS two-target identity + shell + raw exec/EOF + 1MiB SFTP hash + owner/login isolation + verified replay + device revoke passed');
} finally {lane.close();}
