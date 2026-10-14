import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import { RouteLifetime } from '../src/state.ts';
const url = text => 'data:text/javascript;base64,' + Buffer.from(text).toString('base64');
const mockURL = url(`
export class Terminal {
 static instances=[]; constructor(options){this.options=options;this.cols=80;this.rows=24;this.writes=[];Terminal.instances.push(this);}
 loadAddon(){} open(parent){this.parent=parent;} resize(cols,rows){this.cols=cols;this.rows=rows;}
 onData(handler){this.input=handler;}onBinary(handler){this.binary=handler;}attachCustomKeyEventHandler(handler){this.key=handler;}
 write(bytes,callback){this.writes.push({bytes:[...bytes],callback});}focus(){}getSelection(){return 'selected';}paste(text){this.input(text);}dispose(){this.disposed=true;}
}
export class FitAddon { proposeDimensions(){return {cols:120,rows:40};} }
export class SearchAddon { findNext(){return true;}findPrevious(){return true;} }
`);
let source = ts.transpileModule(await readFile(new URL('../src/terminal.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
source = source.replace(/^import ['"].*\.css['"];\s*$/gm,'').replaceAll('import.meta.env.DEV','false');
for(const name of ['@xterm/xterm','@xterm/addon-fit','@xterm/addon-search'])source=source.replace(`from '${name}'`,`from '${mockURL}'`);
for(const name of ['api','state','protocol','terminal-protocol'])source=source.replace(`from './${name}'`,`from '${new URL('../src/'+name+'.ts',import.meta.url).href}'`);
const {mountTerminalSession,OfflineTerminalClient}=await import(url(source)),{Terminal}=await import(mockURL);
class Element {
 constructor(tag){this.tagName=tag;this.children=[];this.value='';this.offsetWidth=1280;this.offsetHeight=720;this.listeners={};}
 append(...values){this.children.push(...values);}replaceChildren(...values){this.children=values;}remove(){}setAttribute(){}addEventListener(name,callback){this.listeners[name]=callback;}removeEventListener(name){delete this.listeners[name];}
}
const flush=async()=>{for(let n=0;n<8;n++)await new Promise(resolve=>setImmediate(resolve));};
const target={asset:{id:'a',protocol:'ssh'},account:{id:'b'}};
const ticket=()=>({session_id:'s',connection_id:'c',target_protocol:'ssh',stream_protocol:'bastion.ssh.v1',ws_token:'ticket-secret'});
function setup(t){
 const original={document:globalThis.document,WebSocket:globalThis.WebSocket,ResizeObserver:globalThis.ResizeObserver,Option:globalThis.Option,location:globalThis.location};
 globalThis.document={createElement:tag=>new Element(tag)};globalThis.Option=class extends Element{constructor(text,value){super('option');this.text=text;this.value=value;}};globalThis.location={origin:'https://bastion.test'};
 const observers=[];globalThis.ResizeObserver=class{constructor(handler){this.handler=handler;observers.push(this);}observe(){}disconnect(){this.disconnected=true;}};
 const sockets=[];globalThis.WebSocket=class{static OPEN=1;constructor(url,protocols){this.url=url;this.protocols=protocols;this.protocol=protocols[0];this.readyState=1;this.bufferedAmount=0;this.sent=[];sockets.push(this);}send(bytes){this.sent.push([...bytes]);}close(code){this.closed=code;this.readyState=3;}};
 t.after(()=>{for(const [key,value] of Object.entries(original)){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}});
 return {root:new Element('main'),sockets,observers};
}
test('SSH waits for ready; render ACK follows xterm write, and stale callbacks cannot send input',async t=>{
 const {root,sockets,observers}=setup(t),life=new RouteLifetime(),issued=ticket(),errors=[],statuses=[];
 const api={session:async()=>issued,connection:async()=>({failure:null})};
 mountTerminalSession(root,api,life,()=>target,text=>statuses.push(text),error=>errors.push(error),()=>true);
 root.children[0].children[0].onclick();await flush();const socket=sockets[0],term=Terminal.instances.at(-1);
 assert.deepEqual(socket.protocols,['bastion.ssh.v1','ticket-secret']);assert.equal(issued.ws_token,'');assert(!socket.url.includes('secret'));
 term.input('before ready');assert.deepEqual(socket.sent,[]);
 const receive=bytes=>socket.onmessage({data:Uint8Array.from(bytes).buffer});receive([2,0,80,0,24]);receive([3]);
 assert.equal(term.options.disableStdin,false);assert.deepEqual(socket.sent[0],[2,0,120,0,40]);
 receive([1,0xe4,0xb8]);assert.deepEqual(term.writes[0].bytes,[0xe4,0xb8]);assert.equal(socket.sent.length,1);
 term.writes[0].callback();assert.deepEqual(socket.sent[1],[4,0,0,0,3]);term.input('中😀');assert.equal(socket.sent.at(-1)[0],1);
 receive([1,0xad]);const callback=term.writes.at(-1).callback,count=socket.sent.length;
 life.dispose();callback();term.input('stale');assert.equal(socket.sent.length,count);assert.equal(socket.closed,1000);assert(term.disposed);assert(observers[0].disconnected);assert.deepEqual(errors,[]);
});
test('disposing a pending session cancels request and never opens a socket',async t=>{
 const {root,sockets}=setup(t),life=new RouteLifetime();let resolve,signal;
 const api={session:(_a,_b,_display,value)=>{signal=value;return new Promise(done=>resolve=done);}};
 mountTerminalSession(root,api,life,()=>target,()=>{},()=>{},()=>true);root.children[0].children[0].onclick();await flush();life.dispose();assert(signal.aborted);resolve(ticket());await flush();assert.equal(sockets.length,0);
});
test('toolbar paste counts as interaction, while terminal query replies do not',async t=>{
 const {root,sockets}=setup(t),life=new RouteLifetime();const previous=Object.getOwnPropertyDescriptor(globalThis,'navigator');
 Object.defineProperty(globalThis,'navigator',{configurable:true,value:{clipboard:{readText:async()=> '中😀'}}});t.after(()=>{if(previous)Object.defineProperty(globalThis,'navigator',previous);else delete globalThis.navigator;});
 const api={session:async()=>ticket(),connection:async()=>({failure:null})};mountTerminalSession(root,api,life,()=>target,()=>{},error=>{throw error;},()=>true);
 root.children[0].children[0].onclick();await flush();const socket=sockets[0],term=Terminal.instances.at(-1);socket.onopen();socket.onmessage({data:Uint8Array.of(3).buffer});socket.sent=[];
 term.input('\x1b[0n');assert.equal(socket.sent.length,1);assert.equal(socket.sent[0][0],1);socket.sent=[];
 root.children[0].children.find(item=>item.textContent==='粘贴').onclick();await flush();assert.equal(socket.sent[0][0],5);assert.equal(socket.sent[1][0],1);life.dispose();
});
test('offline xterm only renders output and resize, with no network or stdin',async t=>{
 const {root,sockets}=setup(t),controller=new AbortController(),player=new OfflineTerminalClient(root,controller.signal),term=player.terminal;
 assert.equal(term.options.disableStdin,true);await player.feed(Uint8Array.of(2,0,100,0,30));assert.equal(term.cols,100);
 let rendered=false;const pending=player.feed(Uint8Array.of(1,27,91,109)).then(()=>rendered=true);await flush();assert.equal(rendered,false);term.writes[0].callback();await pending;
 assert.equal(sockets.length,0);await assert.rejects(player.feed(Uint8Array.of(3)),/REPLAY_READY/);player.close();assert(term.disposed);
});
test('plain Ctrl+V is left to the browser paste, other Ctrl keys still reach the target',async t=>{
 const {root}=setup(t),life=new RouteLifetime();
 const api={session:async()=>ticket(),connection:async()=>({failure:null})};mountTerminalSession(root,api,life,()=>target,()=>{},error=>{throw error;},()=>true);
 root.children[0].children[0].onclick();await flush();const term=Terminal.instances.at(-1);
 const key=(key,mods={})=>term.key({type:'keydown',key,ctrlKey:false,shiftKey:false,altKey:false,metaKey:false,preventDefault(){},...mods});
 assert.equal(key('v',{ctrlKey:true}),false,'xterm must not turn Ctrl+V into ^V');
 assert.equal(key('V',{ctrlKey:true}),false);
 assert.equal(key('c',{ctrlKey:true}),true,'Ctrl+C still interrupts the remote');
 assert.equal(key('v',{ctrlKey:true,altKey:true}),true);
 assert.equal(key('v'),true);life.dispose();
});
