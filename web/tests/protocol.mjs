import assert from 'node:assert/strict';
import test from 'node:test';
import { serializeInstruction, validateDisplay, validateInstruction, DEFAULT_DISPLAY, MAX_INSTRUCTION, streamURL, requireHTTPS } from '../src/protocol.ts';
test('scalar wire lengths, not UTF-16 length or UTF-8 byte count',()=>{
 assert.equal(serializeInstruction(['name','中文😀']), '4.name,3.中文😀;');
 assert.throws(()=>serializeInstruction(['name','\ud800']),/UNICODE/);
 assert.throws(()=>serializeInstruction(['name','x'.repeat(MAX_INSTRUCTION)]),/TOO_LARGE/);
});
test('display defaults and ceilings align with backend',()=>{
 assert.deepEqual(DEFAULT_DISPLAY,{width:1280,height:720,dpi:96});
 for(const value of [{width:3840,height:2160,dpi:192},{width:1,height:1,dpi:48}]) assert.equal(validateDisplay(value),value);
 for(const value of [{...DEFAULT_DISPLAY,width:3841},{...DEFAULT_DISPLAY,height:2161},{...DEFAULT_DISPLAY,dpi:47},{...DEFAULT_DISPLAY,width:1.5}]) assert.throws(()=>validateDisplay(value));
});
test('stream policy blocks forbidden purposes without blocking image blob/ack/end',()=>{
 for(const opcode of ['audio','video','file','pipe','filesystem','connect','select','args','nest']) assert.throws(()=>validateInstruction(opcode,[]),/FORBIDDEN/);
 validateInstruction('clipboard',['0','text/plain']);assert.throws(()=>validateInstruction('clipboard',['0','text/html']),/FORBIDDEN/);
 for(const opcode of ['img','blob','ack','end','sync','size']) assert.doesNotThrow(()=>validateInstruction(opcode,opcode==='size'?['0','1280','720']:[]));
});
test('same-origin WSS and explicit loopback development only',()=>{
 assert.equal(streamURL('https://test.invalid','id /?',false),'wss://test.invalid/api/v1/sessions/id%20%2F%3F/stream');
 assert.equal(streamURL('http://localhost:5173','id',true),'ws://localhost:5173/api/v1/sessions/id/stream');
 assert.throws(()=>streamURL('http://remote.test','id',true)); assert.throws(()=>requireHTTPS('http:',false));
});
