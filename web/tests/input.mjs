import assert from 'node:assert/strict';
import test from 'node:test';
import {nativeBrowser,nativeGuac,setupGuac,loadSource} from './guac-helper.js';
import {RouteLifetime} from '../src/state.ts';
class Element{
 constructor(tag){this.tagName=tag;this.listeners=[];this.children=[];this.style={};this.value='';this.clientWidth=640;this.clientHeight=360;this.clientTop=this.clientLeft=this.scrollTop=this.scrollLeft=0;}
 append(...values){for(const value of values){value.parent=this;this.children.push(value);}}replaceChildren(...values){this.children=[];this.append(...values);if(this.tagName==='select'&&values.length)this.value=values[0].value;}remove(){if(this.parent)this.parent.children=this.parent.children.filter(x=>x!==this);this.parent=null;}
 addEventListener(type,fn,capture=false){this.listeners.push({type,fn,capture});}removeEventListener(type,fn){this.listeners=this.listeners.filter(x=>x.type!==type||x.fn!==fn);}
 event(type,props={}){const e={type,target:this,preventDefault(){this.prevented=true;},stopPropagation(){},stopImmediatePropagation(){this.stopped=true;},getModifierState(){return false;},...props};const ancestors=[];for(let p=this.parent;p;p=p.parent)ancestors.unshift(p);for(const p of ancestors){for(const row of p.listeners.filter(x=>x.type===type&&x.capture)){row.fn(e);if(e.stopped)return e;}}for(const row of [...this.listeners.filter(x=>x.type===type)].sort((a,b)=>Number(b.capture)-Number(a.capture))){row.fn(e);if(e.stopped)break;}return e;}
 setAttribute(){}focus(){globalThis.document.activeElement=this;this.event('focus');}click(){if(!this.disabled)this.onclick?.();}select(){}
 contains(value){return this===value||this.children.some(x=>x.contains(value));}getBoundingClientRect(){return {left:0,top:0};}
}
const flatten=root=>[root,...root.children.flatMap(flatten)],flush=async()=>{for(let i=0;i<10;i++)await new Promise(resolve=>setTimeout(resolve,0));};
class Socket{static OPEN=1;constructor(){this.readyState=1;this.protocol='bastion.guac.v1';this.bufferedAmount=0;this.sent=[];Socket.latest=this;}send(value){this.sent.push(new TextDecoder().decode(value));}close(){this.readyState=3;this.closed=true;}}
test('official input commits IME once, bounds scaled mouse edges and blur release, and never resizes VNC remotely',async t=>{
 const old=Object.fromEntries(['document','window','WebSocket','ResizeObserver','Option','location'].map(key=>[key,globalThis[key]]));
 const body=new Element('body'),doc=new Element('document');doc.body=body;doc.activeElement=body;doc.createElement=tag=>new Element(tag);
 const win=new Element('window');Object.assign(win,{setTimeout,clearTimeout,setInterval,clearInterval});
 Object.assign(globalThis,{document:doc,window:win,WebSocket:Socket,Option:class extends Element{constructor(text,value){super('option');this.textContent=text;this.value=value;}},location:{origin:'https://test.invalid'},ResizeObserver:class{constructor(callback){this.callback=callback;this.constructor.latest=this;}observe(){}disconnect(){this.disconnected=true;}}});
 nativeBrowser(doc,win);setupGuac();
 let mouse;const Mouse=function(element){mouse=new nativeGuac.Mouse(element);return mouse;};Mouse.State=nativeGuac.Mouse.State;globalThis.Guacamole.Mouse=Mouse;
 const {mountSession}=(await loadSource('guac')).module;
 const life=new RouteLifetime(),root=new Element('section');body.append(root);let protocol='vnc',issued=0;const failures=[];
 const api={session:async()=>{issued++;return {session_id:'s',connection_id:'c',target_protocol:protocol,ws_token:'token'};},connection:async()=>({})};
 let approve; const prepare=()=>new Promise(resolve=>{approve=resolve;});
 const update=mountSession(root,api,life,()=>({asset:{id:'a',name:'Host',protocol},account:{id:'c',label:'Target'}}),()=>{},e=>failures.push(e),()=>true,prepare);
 t.after(()=>{life.dispose();Object.assign(globalThis,old);});
 const connect=flatten(root).find(x=>x.tagName==='button'&&x.textContent.includes('重连'));connect.click();connect.click();await flush();assert.equal(issued,0);assert.equal(connect.disabled,true);approve(false);await flush();assert.equal(issued,0);assert.equal(connect.disabled,false);connect.click();await flush();approve(true);await flush();assert.equal(issued,1);const socket=Socket.latest;socket.onopen();socket.onmessage({data:new TextEncoder().encode('4.sync,1.0;').buffer});
 const input=flatten(root).find(x=>x.tagName==='textarea');assert(input);assert.equal(doc.listeners.filter(x=>x.type==='keydown').length,1);assert(input.listeners.some(x=>x.type==='keydown'));
 input.focus();await flush();socket.sent=[];
 input.event('compositionstart',{data:''});input.event('input',{data:'zhong',isComposing:true});input.event('keydown',{key:'Process',keyCode:229,isComposing:true});assert.equal(socket.sent.filter(x=>x.startsWith('3.key')).length,0);
 input.event('compositionend',{data:'中😀'});input.event('input',{data:'中😀',isComposing:false});
 const keys=socket.sent.filter(x=>x.startsWith('3.key'));assert.equal(keys.length,4);assert.equal(keys.filter(x=>x.endsWith(',1.1;')).length,2);
 input.event('keydown',{key:'Shift',keyCode:16,which:16,shiftKey:true});mouse.move({x:100,y:50});mouse.press('left');
 assert(socket.sent.some(x=>x==='5.mouse,3.200,3.100,1.1;'));
 input.event('blur');assert(socket.sent.some(x=>x==='5.mouse,3.200,3.100,1.0;'));assert.equal(mouse.currentState.left,false);assert(socket.sent.some(x=>x==='3.key,5.65505,1.0;'));
 input.focus();mouse.move({x:-0.25,y:-0.25});assert.equal(socket.sent.at(-1),'5.mouse,1.0,1.0,1.0;');
 mouse.move({x:640.25,y:360.25});mouse.press('left');assert.equal(socket.sent.at(-1),'5.mouse,4.1279,3.719,1.1;');
 input.event('blur');assert.equal(socket.sent.at(-1),'5.mouse,4.1279,3.719,1.0;');
 input.focus();const clipboardKeys=socket.sent.filter(x=>x.startsWith('3.key')).length;
 assert(input.event('keydown',{key:'v',ctrlKey:true}).stopped);
 const paste=input.event('paste',{clipboardData:{getData:()=> 'Hello é'}});assert(paste.prevented && paste.stopped);
 const clipboard=Guacamole.Client.latest.streams.get(0);clipboard.onack({code:0,message:'OK'});clipboard.onack({code:0,message:'OK'});await flush();
 assert(socket.sent.some(x=>x==='9.clipboard,1.0,10.text/plain;'));assert(socket.sent.some(x=>x==='4.blob,1.0,12.SGVsbG8gw6k=;'));
 assert.equal(socket.sent.filter(x=>x.startsWith('3.key')).length,clipboardKeys+4,JSON.stringify(socket.sent.filter(x=>x.startsWith('3.key'))));
 const observer=ResizeObserver.latest;observer.callback();await new Promise(resolve=>setTimeout(resolve,120));assert(!socket.sent.some(x=>x.startsWith('4.size')));
 flatten(root).find(x=>x.tagName==='button'&&x.textContent==='断开').click();assert(socket.closed);assert.equal(failures.length,0);
 protocol='ssh';connect.click();await flush();approve(true);await flush();Socket.latest.onopen();Socket.latest.onmessage({data:new TextEncoder().encode('4.sync,1.0;').buffer});const before=Socket.latest.sent.length;input.event('compositionend',{data:'stale previous route'});assert.equal(Socket.latest.sent.length,before);
 await new Promise(resolve=>setTimeout(resolve,120));assert.equal(Socket.latest.sent.filter(x=>x==='4.size,3.640,3.360;').length,1,'ready sends viewport dimensions without an observer change');
 observer.callback();await new Promise(resolve=>setTimeout(resolve,120));assert.equal(Socket.latest.sent.filter(x=>x==='4.size,3.640,3.360;').length,1,'unchanged dimensions do not resend');
 const viewport=flatten(root).find(x=>x.className==='guac-viewport');viewport.clientWidth=800;observer.callback();await new Promise(resolve=>setTimeout(resolve,120));assert(Socket.latest.sent.some(x=>x==='4.size,3.800,3.360;'));
 // A scrollbar must not request smaller remote dimensions and start a resize loop.
 viewport.offsetWidth=802;viewport.offsetHeight=362;viewport.clientLeft=viewport.clientTop=1;
 const beforeScrollbar=Socket.latest.sent.filter(x=>x.startsWith('4.size')).length;
 viewport.clientWidth=785;viewport.clientHeight=345;observer.callback();await new Promise(resolve=>setTimeout(resolve,120));
 assert.equal(Socket.latest.sent.filter(x=>x.startsWith('4.size')).length,beforeScrollbar);
 viewport.clientWidth=800;viewport.clientHeight=360;observer.callback();await new Promise(resolve=>setTimeout(resolve,120));
 assert.equal(Socket.latest.sent.filter(x=>x.startsWith('4.size')).length,beforeScrollbar);assert.equal(viewport.style.overflow,'hidden');
 input.focus();mouse.move({x:200,y:100});assert.equal(Guacamole.Client.latest.display.cursorShown,true);mouse.press('left');
 const displayElement=Guacamole.Client.latest.display.getElement();displayElement.event('mouseout',{relatedTarget:body});assert.equal(Guacamole.Client.latest.display.cursorShown,false);assert.equal(mouse.currentState.left,false);
 mouse.move({x:100,y:50});assert.equal(Guacamole.Client.latest.display.cursorShown,true);await flush();
 const previousKeys=Socket.latest.sent.filter(x=>x.startsWith('3.key')).length;
 input.event('compositionstart',{data:''});input.event('compositionend',{data:'中😀'});
 assert.equal(Socket.latest.sent.filter(x=>x.startsWith('3.key')).length,previousKeys);assert.match(failures.at(-1).message,/整段组合文本未发送/);
 input.event('compositionstart',{data:''});input.event('compositionend',{data:'中文'});
 assert.equal(Socket.latest.sent.filter(x=>x.startsWith('3.key')).length,previousKeys+4);
 life.dispose();assert(Socket.latest.closed);
});
