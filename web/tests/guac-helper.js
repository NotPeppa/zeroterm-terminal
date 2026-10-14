import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';
const context={window:{btoa,atob}};vm.createContext(context);vm.runInContext(await readFile(new URL('../public/guacamole/all.js',import.meta.url),'utf8'),context);
export const nativeGuac=context.Guacamole;
export function nativeBrowser(document, window) { context.document = document; context.window = Object.assign(window,{btoa,atob}); context.navigator = { platform: 'Win32' }; }
export class Display {
 constructor(){this.instructions=[];this.callbacks=[];this.autoFlush=true;this.element=globalThis.document?.createElement('div')??{};}
 getElement(){return this.element;}getWidth(){return 1280;}getHeight(){return 720;}getScale(){return 0.5;}scale(){}
 showCursor(shown){this.cursorShown=shown;}
 flush(callback){if(this.autoFlush)callback();else this.callbacks.push(callback);}
}
export class Client {
 constructor(tunnel){this.tunnel=tunnel;this.display=new Display();this.streams=new Map();this.nextStream=0;tunnel.oninstruction=(opcode,args)=>{this.display.instructions.push([opcode,[...args]]);if(opcode==='ack')this.streams.get(Number(args[0]))?.onack?.({code:Number(args[2]),message:args[1]});};Client.latest=this;}
 getDisplay(){return this.display;}connect(data){this.tunnel.connect(data);}disconnect(){this.disconnected=true;this.tunnel.sendMessage('disconnect');this.tunnel.disconnect();}
 sendKeyEvent(pressed,key){this.tunnel.sendMessage('key',key,pressed);}sendMouseState(state,scaled){const scale=scaled?this.display.getScale():1;this.tunnel.sendMessage('mouse',Math.floor(state.x/scale),Math.floor(state.y/scale),state.left?1:0);}sendSize(width,height){this.tunnel.sendMessage('size',width,height);}
 createClipboardStream(type){const index=this.nextStream++;const stream={index,onack:null,sendBlob:data=>this.tunnel.sendMessage('blob',index,data),sendEnd:()=>this.tunnel.sendMessage('end',index)};this.streams.set(index,stream);this.tunnel.sendMessage('clipboard',index,type);return stream;}
}
export function setupGuac(){globalThis.Guacamole={...nativeGuac,Client};}
const moduleURL=source=>'data:text/javascript;base64,'+Buffer.from(source).toString('base64');
export async function loadSource(name,replacements={}){
 let source=ts.transpileModule(await readFile(new URL('../src/'+name+'.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText.replaceAll('import.meta.env.DEV','false');
 for(const key of ['api','state','protocol','replay'])source=source.replace("from './"+key+"'","from '"+new URL('../src/'+key+'.ts',import.meta.url).href+"'");
 for(const [key,value] of Object.entries(replacements))source=source.replace("from './"+key+"'","from '"+value+"'");
 return {url:moduleURL(source),module:await import(moduleURL(source))};
}
