import assert from 'node:assert/strict';
import test from 'node:test';
import {setupGuac,loadSource} from './guac-helper.js';
import {RouteLifetime} from '../src/state.ts';
import {serializeInstruction,MAX_PAYLOAD,MAX_INSTRUCTION,MAX_BUFFER} from '../src/protocol.ts';
setupGuac();const {GuacStream,GuacTunnelClient}=(await loadSource('guac')).module;
const bytes=text=>new TextEncoder().encode(text);
test('official parser receives continuous fatal UTF-8 decoder output across every byte boundary',()=>{
 const seen=[],stream=new GuacStream((op,args)=>seen.push([op,...args]));const input=bytes(serializeInstruction(['name','中文😀'])+serializeInstruction(['sync','1']));
 for(const byte of input)stream.feed(Uint8Array.of(byte));stream.finish();assert.deepEqual(seen,[['name','中文😀'],['sync','1']]);
});
test('fragmented display img/blob/ack/end survives while forbidden stream purposes fail',()=>{
 const seen=[],stream=new GuacStream((op,args)=>seen.push([op,...args]));
 for(const opcode of ['img','blob','ack','end'])stream.feed(bytes(serializeInstruction([opcode,'0'])));stream.finish();assert.deepEqual(seen.map(x=>x[0]),['img','blob','ack','end']);
 for(const op of ['audio','video','file','pipe'])assert.throws(()=>new GuacStream(()=>{}).feed(bytes(serializeInstruction([op,'0']))),/FORBIDDEN/);
 const text=[];new GuacStream((op,args)=>text.push([op,...args])).feed(bytes(serializeInstruction(['clipboard','0','text/plain'])));assert.deepEqual(text,[['clipboard','0','text/plain']]);
 assert.throws(()=>new GuacStream(()=>{}).feed(bytes(serializeInstruction(['clipboard','0','image/png']))),/FORBIDDEN/);
});
test('invalid and truncated UTF-8/instructions and oversized chunks fail closed',()=>{
 assert.throws(()=>new GuacStream(()=>{}).feed(Uint8Array.of(255)));
 const utf=new GuacStream(()=>{});utf.feed(Uint8Array.of(0xe4));assert.throws(()=>utf.finish());
 const partial=new GuacStream(()=>{});partial.feed(bytes('4.sync,1.'));assert.throws(()=>partial.finish(),/TRUNCATED/);
 assert.throws(()=>new GuacStream(()=>{}).feed(new Uint8Array(MAX_PAYLOAD+1)),/CHUNK/);
 const huge=new GuacStream(()=>{});huge.feed(bytes('4.name,8388609.'));const block=bytes('a'.repeat(MAX_PAYLOAD));assert.throws(()=>{for(let i=0;i<MAX_INSTRUCTION/MAX_PAYLOAD+1;i++)huge.feed(block);},/TOO_LARGE/);
});
class Socket {
 static OPEN=1;static created=[];
 constructor(url,protocols){this.url=url;this.protocols=protocols;this.protocol='bastion.guac.v1';this.readyState=1;this.bufferedAmount=0;this.sent=[];Socket.created.push(this);}
 send(data){this.sent.push(data);}close(code){this.closeCode=code;this.closed=true;this.readyState=3;}
}
const target={asset:{id:'a',name:'Host',protocol:'ssh'},account:{id:'c',label:'Root',username:'root'}};
const ticket=()=>({session_id:'s',connection_id:'conn',target_protocol:'ssh',stream_protocol:'bastion.guac.v1',ws_token:'one-time-token'});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function rig(t,options={}){
 const previous={WebSocket:globalThis.WebSocket,location:globalThis.location};globalThis.WebSocket=Socket;globalThis.location={origin:'https://gateway.test'};
 const life=new RouteLifetime(),errors=[],calls=[],tickets=[],diag=[],status=[];
 const conn=new GuacTunnelClient({session:async(...args)=>{calls.push(args);const value=ticket();tickets.push(value);return value;},connection:async id=>{diag.push(id);return {};},...options},life,text=>status.push(text),(error,target)=>errors.push({error,target}));
 t.after(()=>{life.dispose();Object.assign(globalThis,previous);});return {life,conn,errors,calls,tickets,diag,status};
}
test('ticket display, cookie WS URL and non-echoed secret subprotocol are used once; binary scalar serialization',async t=>{
 const r=rig(t);await r.conn.connect(target);const socket=r.conn.socket;
 assert.deepEqual(r.calls[0].slice(0,3),['a','c',{width:1280,height:720,dpi:96}]);assert.equal(socket.url,'wss://gateway.test/api/v1/sessions/s/stream');assert.deepEqual(socket.protocols,['bastion.guac.v1','one-time-token']);assert.equal(r.tickets[0].ws_token,'');
 socket.onopen(); assert.equal(r.conn.ready,false); assert.match(r.status.at(-1),/正在建立/); r.conn.tunnel.sendMessage('key','😀',1); assert.equal(socket.sent.length,0);
 socket.onmessage({data:bytes(serializeInstruction(['name','中文😀'])).buffer}); assert.equal(r.conn.ready,true); assert.match(r.status.at(-1),/显示流已就绪/); r.conn.tunnel.sendMessage('key','😀',1); assert(socket.sent[0] instanceof Uint8Array); assert.equal(new TextDecoder().decode(socket.sent[0]),'3.key,1.😀,1.1;'); assert.deepEqual(r.conn.client.display.instructions,[['name',['中文😀']]]);assert.equal(r.errors.length,0);
});
test('binary-only input, outbound queue and non-echo protocol mismatch close without replay',async t=>{
 for(const failure of ['text','queue','echo']){const r=rig(t);await r.conn.connect(target);const socket=r.conn.socket;
 if(failure==='text')socket.onmessage({data:'4.sync,1.0;'});if(failure==='queue'){socket.onmessage({data:bytes(serializeInstruction(['sync','1'])).buffer});socket.bufferedAmount=MAX_BUFFER;r.conn.tunnel.sendMessage('key','1','1');}if(failure==='echo'){socket.protocol='one-time-token';socket.onopen();}
 assert(socket.closed);assert.equal(socket.closeCode,4000);assert.equal(r.calls.length,1);assert.equal(r.errors.length,1);r.life.dispose();}
});
test('graceful route disposal queues Guacamole disconnect before normal WS close and invalidation',async t=>{
 const r=rig(t);await r.conn.connect(target);const socket=r.conn.socket;socket.onopen();let validAtSend=false;
 const send=socket.send.bind(socket);socket.send=data=>{assert.equal(socket.readyState,1);assert.equal(r.life.signal.aborted,false);validAtSend=true;send(data);};
 const close=socket.close.bind(socket);socket.close=code=>{assert.equal(new TextDecoder().decode(socket.sent.at(-1)),'10.disconnect;');assert.equal(r.life.signal.aborted,false);close(code);};
 r.life.dispose();assert(validAtSend);assert.equal(socket.closeCode,1000);assert.equal(r.conn.socket,null);assert.equal(r.conn.ready,false);assert.equal(r.errors.length,0);
});
test('disconnect queue failure is explicit and closes as failed without duplicate errors',async t=>{
 const r=rig(t);await r.conn.connect(target);const socket=r.conn.socket;socket.bufferedAmount=MAX_BUFFER;r.conn.close();assert.equal(socket.closeCode,4000);assert.equal(r.errors.length,1);assert.equal(socket.sent.length,0);
});
test('late ticket and saved old callbacks are ignored after route disposal',async t=>{
 let resolve;const r=rig(t,{session:()=>new Promise(done=>{resolve=done;})});const opening=r.conn.connect(target);r.life.dispose();const value=ticket();resolve(value);await opening;assert.equal(value.ws_token,'');assert.equal(r.conn.socket,null);assert.equal(r.errors.length,0);
});
test('old close diagnostics cannot affect a newer attempt and actual socket closes before route invalidation',async t=>{
 let resolve;const r=rig(t,{connection:()=>new Promise(done=>{resolve=done;})});await r.conn.connect(target);const old=r.conn.socket,callbacks={message:old.onmessage,error:old.onerror,open:old.onopen,close:old.onclose};old.onclose({code:1000});await r.conn.connect(target);const current=r.conn.socket;
 resolve({failure:{code:'OLD_ERROR'}});await flush();callbacks.message({data:'bad'});callbacks.error();callbacks.open();callbacks.close({code:1006});assert.equal(r.errors.length,0);assert.equal(r.conn.socket,current);
 let abortedAtClose;current.close=()=>{abortedAtClose=r.life.signal.aborted;};r.life.dispose();assert.equal(abortedAtClose,false);assert(r.life.signal.aborted);
});

test('clipboard UTF-8 uses bounded ACK-paced blobs, including emoji, before desktop paste keys',async t=>{
 const r=rig(t);await r.conn.connect(target);const socket=r.conn.socket;socket.onopen();socket.onmessage({data:bytes(serializeInstruction(['sync','1'])).buffer});
 const text='ab中😀\n'.repeat(5000),pending=r.conn.pasteText(text,{shift:true}),stream=r.conn.client.streams.get(0);
 assert.equal(socket.sent.length,1);assert.equal(new TextDecoder().decode(socket.sent[0]),'9.clipboard,1.0,10.text/plain;');
 for(let i=0;i<30 && !socket.sent.some(value=>new TextDecoder().decode(value).startsWith('3.end'));i++)stream.onack({code:0,message:'OK'});
 await pending;
 const parser=new Guacamole.Parser(),instructions=[];parser.oninstruction=(op,args)=>instructions.push([op,...args]);for(const block of socket.sent)parser.receive(new TextDecoder().decode(block));
 const chunks=instructions.filter(row=>row[0]==='blob').map(row=>Buffer.from(row[2],'base64'));assert(chunks.every(value=>value.length<=6048));for(const chunk of chunks)new TextDecoder('utf-8',{fatal:true}).decode(chunk);assert.equal(Buffer.concat(chunks).toString('utf8'),text);
 const end=instructions.findIndex(row=>row[0]==='end');assert(end>0);assert(instructions.slice(0,end).every(row=>row[0]!=='key'));assert.equal(instructions.at(-1)[0],'key');assert(instructions.some(row=>row[0]==='key' && row[1]==='86' && row[2]==='1'));
 await assert.rejects(r.conn.pasteText('x'.repeat(256*1024+1)),/TOO_LARGE/);
 await assert.rejects(r.conn.pasteText('\ud800'),/UNICODE/);
 r.conn.close();await assert.rejects(r.conn.pasteText('x'),/NOT_READY/);
});

test('clipboard receive handles split Unicode, clears on close and ignores stale completions',async t=>{
 const r=rig(t);await r.conn.connect(target);r.conn.socket.onopen();r.conn.socket.onmessage({data:bytes(serializeInstruction(['sync','1'])).buffer});
 const ack=[],stream={sendAck:(message,code)=>ack.push(code)};r.conn.client.onclipboard(stream,'text/plain');
 const payload=Buffer.from('中😀');for(const byte of payload)stream.onblob(Buffer.from([byte]).toString('base64'));stream.onend();assert.equal(r.conn.clipboardText,'中😀');assert(ack.every(code=>code===0));
 const stale={sendAck(){}};r.conn.client.onclipboard(stale,'text/plain');r.conn.close();stale.onblob(payload.toString('base64'));stale.onend();assert.equal(r.conn.clipboardText,'');
});

test('clipboard target rejection closes the session without retrying a partial paste',async t=>{
 const r=rig(t);await r.conn.connect(target);const socket=r.conn.socket;socket.onmessage({data:bytes(serializeInstruction(['sync','1'])).buffer});
 const pending=r.conn.pasteText('text'),rejected=assert.rejects(pending,/CLIPBOARD_REJECTED/);r.conn.client.streams.get(0).onack({code:0x030f,message:'unsupported'});await rejected;assert(socket.closed);assert.equal(r.calls.length,1);
});
test('standard VNC clipboard rejects Unicode that would be silently replaced',async t=>{
 const r=rig(t,{session:async()=>({...ticket(),target_protocol:'vnc'})});await r.conn.connect({...target,asset:{...target.asset,protocol:'vnc'}});r.conn.socket.onmessage({data:bytes(serializeInstruction(['sync','1'])).buffer});
 await assert.rejects(r.conn.pasteText('中😀'),/VNC_CLIPBOARD_CHARSET/);assert.equal(r.conn.socket.sent.length,0);
});
