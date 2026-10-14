import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeBase64, readNDJSON, ReplaySequence } from '../src/replay.ts';
const meta={type:'meta',seq:0,elapsed_us:0,format_version:2,connection_id:'connection',target_protocol:'ssh',width:1280,height:720,dpi:96};
const end={type:'end',seq:2,elapsed_us:2,reason:'closed'};
test('strict v2 sequence directly binds connection and accepts display chunks only',()=>{
 const seq=new ReplaySequence('connection');seq.parse(JSON.stringify(meta));
 const output=seq.parse(JSON.stringify({type:'output',seq:1,elapsed_us:1,data_base64:'/wA='}));assert.deepEqual([...decodeBase64(output.data_base64)],[255,0]);
 seq.parse(JSON.stringify(end));seq.finish();assert.throws(()=>seq.parse(JSON.stringify({...end,seq:3})));
 for(const value of [{...meta,format_version:1},{...meta,target_protocol:'other'},{...meta,width:3841},{...meta,dpi:47},{...meta,connection_id:'other'}]) assert.throws(()=>new ReplaySequence('connection').parse(JSON.stringify(value)));
});
test('partial, duplicate/end, sequence gaps, unknown type, backward time and base64 are errors',()=>{
 const seq=new ReplaySequence();seq.parse(JSON.stringify(meta));assert.throws(()=>seq.finish(),/PARTIAL/);
 for(const value of [{...end},{type:'resize',seq:1,elapsed_us:1},{type:'output',seq:1,elapsed_us:1,data_base64:'!!!!'},{type:'end',seq:1,elapsed_us:-1,reason:'closed'}]) assert.throws(()=>seq.parse(JSON.stringify(value)));
 assert.throws(()=>decodeBase64('AA=='.repeat(9000))); assert.throws(()=>decodeBase64('AB=='));
});
test('streaming NDJSON accepts one-byte UTF-8 fragments and rejects invalid/truncated text or EOF tails',async()=>{
 const bytes=Buffer.from(JSON.stringify({...meta,connection_id:'中文😀'})+'\n'+JSON.stringify({...end,seq:1})+'\n');
 const stream=new ReadableStream({start(c){for(const byte of bytes)c.enqueue(Uint8Array.of(byte));c.close();}});const seq=new ReplaySequence();
 await readNDJSON(new Response(stream,{headers:{'Content-Type':'application/x-ndjson'}}),new AbortController().signal,async line=>{seq.parse(line);});seq.finish();
 for(const bytes of [Buffer.from('{}'),Buffer.from([0xff,10]),Buffer.from([0xe4,0xb8])]) await assert.rejects(readNDJSON(new Response(bytes,{headers:{'Content-Type':'application/x-ndjson'}}),new AbortController().signal,async()=>{}));
});
