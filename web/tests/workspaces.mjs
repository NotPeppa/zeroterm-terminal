import assert from 'node:assert/strict';
import test from 'node:test';
import {setupGuac,loadSource,Client} from './guac-helper.js';
import {RouteLifetime} from '../src/state.ts';
import {serializeInstruction} from '../src/protocol.ts';
setupGuac();const guac=await loadSource('guac');const {OfflineGuacClient,mountReplay}=(await loadSource('workspaces',{guac:guac.url})).module;
class Element{
 constructor(tag){this.tagName=tag;this.children=[];this._text='';this.value='';this.clientWidth=1280;this.clientHeight=720;this.disabled=false;this.hidden=false;
    const classes=new Set();
    Object.defineProperty(this,'className',{get:()=>[...classes].join(' '),set:value=>{classes.clear();String(value).split(/\s+/).filter(Boolean).forEach(name=>classes.add(name));},enumerable:true,configurable:true});
    this.classList={add:(...names)=>names.forEach(name=>classes.add(name)),remove:(...names)=>names.forEach(name=>classes.delete(name)),contains:name=>classes.has(name),toggle:(name,on)=>{const next=on===undefined?!classes.has(name):!!on;if(next)classes.add(name);else classes.delete(name);return next;}};}
 get textContent(){return this._text+this.children.map(x=>x.textContent).join('');}set textContent(value){this._text=String(value);this.children=[];}
 append(...values){this.children.push(...values);}replaceChildren(...values){this.children=[];this.append(...values);}setAttribute(){}click(){if(!this.disabled)this.onclick?.();}
}
const all=root=>[root,...root.children.flatMap(all)],button=(root,text)=>all(root).find(x=>x.tagName==='button'&&x.textContent===text),flush=async()=>{for(let i=0;i<20;i++)await new Promise(resolve=>setImmediate(resolve));};
function dom(t){const original=globalThis.document;globalThis.document={createElement:tag=>new Element(tag)};t.after(()=>{globalThis.document=original;});return new Element('section');}
const meta={type:'meta',seq:0,elapsed_us:0,format_version:2,connection_id:'conn',target_protocol:'vnc',width:1280,height:720,dpi:96};
const output={type:'output',seq:1,elapsed_us:0,data_base64:Buffer.from(serializeInstruction(['name','回放😀'])).toString('base64')};
const end={type:'end',seq:2,elapsed_us:0,reason:'closed'};
const response=events=>new Response(events.map(x=>JSON.stringify(x)).join('\n')+'\n',{headers:{'Content-Type':'application/x-ndjson'}});
test('offline client has no WebSocket and display.flush applies backpressure',async t=>{
 dom(t);const previous=globalThis.WebSocket;globalThis.WebSocket=class{constructor(){throw Error('Offline opened network');}};t.after(()=>globalThis.WebSocket=previous);
 const controller=new AbortController(),player=new OfflineGuacClient(controller.signal);player.client.display.autoFlush=false;let rendered=false;
 const pending=player.feed(Buffer.from(serializeInstruction(['name','中文😀']))).then(()=>{rendered=true;});await flush();assert.equal(rendered,false);assert.deepEqual(player.client.display.instructions,[['name',['中文😀']]]);
 player.client.display.callbacks.shift()();await pending;player.finish();player.close();assert(player.client.disconnected);
});
test('offline replay cannot expose recorded clipboard data to the browser',async t=>{
 dom(t);const player=new OfflineGuacClient(new AbortController().signal);
 await assert.rejects(player.feed(Buffer.from(serializeInstruction(['clipboard','0','text/plain']))),/REPLAY_CLIPBOARD_FORBIDDEN/);player.close();
});
test('split image stream feeds through end before waiting for display.flush',async t=>{
 dom(t);const controller=new AbortController(),player=new OfflineGuacClient(controller.signal);player.client.display.autoFlush=false;
 await player.feed(Buffer.from(serializeInstruction(['img','7','14','0','image/png','0','0'])));
 assert.equal(player.client.display.callbacks.length,0);
 await player.feed(Buffer.from(serializeInstruction(['blob','7','aA=='])));
 assert.equal(player.client.display.callbacks.length,0);assert.throws(()=>player.finish(),/TRUNCATED_REPLAY_IMAGE/);
 let rendered=false;const finished=player.feed(Buffer.from(serializeInstruction(['end','7']))).then(()=>rendered=true);
 await flush();assert.equal(rendered,false);assert.equal(player.client.display.callbacks.length,1);
 player.client.display.callbacks.shift()();await finished;player.finish();player.close();
});
test('selecting a row only selects it; playing streams v2 output and only end plus clean EOF claims completion; restart rereads',async t=>{
 const root=dom(t),life=new RouteLifetime(),calls=[],errors=[];
 const api={recordings:async()=>({items:[{id:'rec',format_version:2,state:'complete',connection_id:'conn'}],next_cursor:null}),recording:async id=>{calls.push(['detail',id]);return {id,format_version:2,state:'complete',connection_id:'conn'};},recordingContent:async id=>{calls.push(['content',id]);return response([meta,output,end]);}};
  mountReplay(root,api,life,()=>{},error=>errors.push(error));await flush();
  // The landing page pre-selects the first row; selecting alone must not stream anything.
  assert.deepEqual(calls,[]);assert.equal(all(root).find(x=>x.id==='replay-id').value,'rec');assert.match(root.textContent,/已选择这条录制/);
  button(root,'播放 / 从头重播').click();await flush();
 assert.deepEqual(calls,[['detail','rec'],['content','rec']]);assert.equal(errors.length,0);assert.match(root.textContent,/干净 EOF/);assert.deepEqual(Client.latest.display.instructions,[['name',['回放😀']]]);
 button(root,'播放 / 从头重播').click();await flush();assert.equal(calls.length,4);life.dispose();
});
test('unknown format, partial metadata, missing end, extra event and bad UTF-8 remain visible errors',async t=>{
 for(const mode of ['format','partial','end','extra','utf8'])await t.test(mode,async t=>{
 const root=dom(t),life=new RouteLifetime(),errors=[];let reads=0;
 const api={recordings:async()=>({items:[{id:'rec'}],next_cursor:null}),recording:async()=>({id:'rec',format_version:mode==='format'?1:2,state:mode==='partial'?'partial':'complete',connection_id:'conn'}),recordingContent:async()=>{reads++;if(mode==='utf8')return new Response(Uint8Array.of(255),{headers:{'Content-Type':'application/x-ndjson'}});return response(mode==='end'?[meta,output]:mode==='extra'?[meta,output,end,{...end,seq:3}]:[meta,output,end]);}};
  mountReplay(root,api,life,()=>{},error=>errors.push(error));await flush();button(root,'播放 / 从头重播').click();await flush();assert.equal(errors.length,1);assert.match(root.textContent,/不宣称完整/);assert.equal(reads,['format','partial'].includes(mode)?0:1);life.dispose();
 });
});

test('recording rows are named by start time and target, not by ID; the ID stays in the tooltip',async t=>{
 const root=dom(t),life=new RouteLifetime();
 const item={id:'rec-uuid-0000-1111',format_version:2,state:'complete',connection_id:'conn',target_protocol:'ssh',bytes:2048,created_at:'2026-03-04T05:06:07Z',ended_at:null,user_snapshot:'alice',asset_snapshot:'db-prod',target_username:'root'};
 const api={recordings:async()=>({items:[item],next_cursor:null})};
 mountReplay(root,api,life,()=>{},()=>{});await flush();
 const stamp=new Date(item.created_at).toLocaleString('zh-CN',{hour12:false});
 const row=all(root).find(x=>x.tagName==='button'&&x.className.includes('console-target'));
 assert.ok(row.textContent.includes(stamp));assert.match(row.textContent,/db-prod · alice → root/);assert.doesNotMatch(row.textContent,/rec-uuid/);assert.match(row.title,/rec-uuid-0000-1111/);
 const heading=all(root).find(x=>x.tagName==='h1');assert.equal(heading.textContent,stamp);assert.match(heading.title,/rec-uuid-0000-1111/);
 life.dispose();
});
