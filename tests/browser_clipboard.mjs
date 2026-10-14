import {selectBrowserTarget} from './browser_targets.mjs';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import path from 'node:path';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_PACKAGE || 'playwright');
const fixture=JSON.parse(await readFile(process.argv[2],'utf8')),output=process.argv[3],remoteSource=process.env.BASTION_ACCEPTANCE_REMOTE_SOURCE;
assert.match(fixture.server_id,/^zt-guac-v2-[a-z0-9-]+$/);if(process.env.BASTION_ACCEPTANCE_SSH_HOST)assert.match(remoteSource,/^\/var\/tmp\/zt-guac-v2-[a-z0-9-]+\/source$/);
await mkdir(output,{recursive:true});
const result={production_ready:false,windows_nla_verified:false,native_os_ime_verified:false,application_image_id:fixture.application_image_id,engine_image_id:fixture.engine_image_id,profiles:[]};
const browser=await chromium.launch({headless:true,args:['--ignore-certificate-errors-spki-list='+fixture.public_spki]});
const context=await browser.newContext(),page=await context.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:fixture.origin});
async function probe(request){
 const remote=!!process.env.BASTION_ACCEPTANCE_SSH_HOST;
 const args=remote?['-i',process.env.BASTION_ACCEPTANCE_SSH_KEY,'-p',process.env.BASTION_ACCEPTANCE_SSH_PORT || '22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',process.env.BASTION_ACCEPTANCE_SSH_HOST,'python3 '+remoteSource+'/tests/docker_clipboard_probe.py /var/tmp/'+fixture.server_id]:['tests/docker_clipboard_probe.py','/var/tmp/'+fixture.server_id];
 return new Promise((resolve,reject)=>{const child=spawn(remote?'ssh':'python3',args,{stdio:['pipe','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',bytes=>{stdout+=bytes;});child.stderr.on('data',bytes=>{stderr+=bytes;});child.on('error',reject);child.on('close',code=>{if(code)reject(new Error('controlled target probe failed: '+stderr));else{try{resolve(JSON.parse(stdout));}catch(error){reject(error);}}});child.stdin.end(JSON.stringify(request));});
}
async function api(resource){return page.evaluate(async resource=>{const response=await fetch('/api/v1'+resource,{credentials:'same-origin'});if(!response.ok)throw new Error('fixture API '+response.status);return response.json();},resource);}
async function poll(read,accept,timeout=30000){const end=Date.now()+timeout;while(Date.now()<end){const value=await read();if(accept(value))return value;await new Promise(resolve=>setTimeout(resolve,150));}throw new Error('clipboard acceptance deadline');}
async function paste(text){
 if(await page.locator('.terminal-viewport').count()){await page.evaluate(text=>navigator.clipboard.writeText(text),text);await page.locator('.terminal-viewport textarea').focus();await page.keyboard.press('Control+v');return;}

 await page.locator('.guac-viewport textarea, .terminal-viewport textarea').focus();
 await page.locator('#status').evaluate(node=>{node.textContent='等待剪贴板传输完成';});
 await page.locator('.guac-viewport textarea, .terminal-viewport textarea').evaluate((input,text)=>{
   input.dispatchEvent(new KeyboardEvent('keydown',{key:'v',ctrlKey:true,shiftKey:true,bubbles:true,cancelable:true}));
   const data=new DataTransfer();data.setData('text/plain',text);input.dispatchEvent(new ClipboardEvent('paste',{clipboardData:data,bubbles:true,cancelable:true}));
   input.dispatchEvent(new KeyboardEvent('keyup',{key:'v',ctrlKey:true,shiftKey:true,bubbles:true,cancelable:true}));
 },text);
 await page.waitForFunction(()=>document.querySelector('#status').textContent==='文本已发送到目标。',null,{timeout:15000});
}
async function clipboardValue(){
 await page.getByRole('button',{name:'剪贴板',exact:true}).click();const text=await page.getByLabel('剪贴板文本',{exact:true}).inputValue();await page.getByRole('button',{name:'关闭',exact:true}).click();return text;
}
try{
 await page.goto(fixture.origin,{waitUntil:'networkidle'});assert.equal((await api('/info')).server_id,fixture.server_id);
 await page.locator('#username').fill(fixture.username);await page.locator('#password').fill(fixture.password);await page.locator('#login').click();await page.locator('#workspace').waitFor({state:'visible'});
 for(const profile of fixture.profiles.filter(row=>['ssh-password','rdp-tls','vnc-none','vnc-password'].includes(row.label) && (!process.env.BASTION_CLIPBOARD_PROFILE || row.label===process.env.BASTION_CLIPBOARD_PROFILE))){
   console.log('Testing clipboard: '+profile.label);
   const response=await selectBrowserTarget(page,profile.asset_id,profile.account_id);assert.equal(response.status(),201);const ticket=await response.json();ticket.ws_token='';
   await page.waitForFunction(()=>document.querySelector('#status').textContent.includes('目标显示流已就绪') || document.querySelector('#status').textContent.includes('SSH 终端已就绪'),null,{timeout:50000});
   await page.waitForFunction(()=>{const display=document.querySelector('.guac-viewport > div, .terminal-viewport .xterm-screen');return display && display.getBoundingClientRect().width>200 && display.getBoundingClientRect().height>100;});await page.waitForTimeout(1000);
   const display=page.locator('.guac-viewport > div, .terminal-viewport .xterm-screen').first();const box=await display.boundingBox();await page.mouse.click(box.x+30,box.y+30);await page.keyboard.press('Control+c');
   const payload=profile.protocol==='vnc'?'CAFÉ_clipboard':('a'.repeat(2000)+'\n').repeat(3)+(profile.protocol==='rdp'?'中文_clipboard\n':'中😀_clipboard\n'),file='/tmp/ztclip-'+randomUUID().replaceAll('-','');
   const command=profile.protocol==='vnc'?"printf '%s' '"+payload+"' > "+file:"cat > "+file+" <<'ZTCLIP_END'\n"+payload+'ZTCLIP_END';
   await paste(command);
   if(profile.protocol!=='ssh'){
     const label=profile.protocol==='rdp'?'rdp':profile.label;
     assert.equal((await probe({action:'read',profile:label})).text,command,'target clipboard did not receive upload');
   }
   await page.locator('.guac-viewport textarea, .terminal-viewport textarea').focus();await page.keyboard.press('Enter');
   const target=await poll(()=>probe({action:'file',path:file}),row=>row.found);assert.equal(target.text,payload);
   const row={label:profile.label,protocol:profile.protocol,target_paste_roundtrip:true,unicode_clipboard:profile.protocol!=='vnc',connection_id:ticket.connection_id};
   if(profile.protocol==='rdp')row.target_clipboard_limit='Debian xrdp 0.9.x clipboard uses UCS-2; non-BMP target interoperability is not claimed';
   row.non_bmp_clipboard=profile.protocol==='ssh';row.multiple_upload_blobs=profile.protocol!=='vnc';
   if(profile.protocol==='ssh'){
     const marker='ZT_COPY_BACK';await paste("printf '\\033[2J\\033[H%s\\n' '"+marker+"'");await page.keyboard.press('Enter');await page.waitForTimeout(500);
     await page.mouse.move(box.x+10,box.y+15);await page.mouse.down();await page.mouse.move(box.x+220,box.y+15,{steps:20});await page.mouse.up();
     await page.getByLabel('搜索终端文本',{exact:true}).fill(marker);await page.getByRole('button',{name:'下一个',exact:true}).click();await page.getByRole('button',{name:'复制选中',exact:true}).click();const copied=await poll(()=>page.evaluate(()=>navigator.clipboard.readText()),text=>text===marker);assert.equal(copied,marker);
   }else{
     const label=profile.protocol==='rdp'?'rdp':profile.label;
     assert.equal((await probe({action:'read',profile:label})).text,command);
     const marker=profile.protocol==='rdp'?'TARGET中文':'TARGET_café';await probe({action:'set',profile:label,text:marker});
     assert.equal(await poll(clipboardValue,text=>text===marker),marker);
   }
   row.target_copy_roundtrip=true;
   const cached=profile.protocol==='ssh'?await page.evaluate(()=>navigator.clipboard.readText()):await clipboardValue();await page.getByRole('button',{name:profile.protocol==='ssh'?'复制选中':'复制',exact:true}).click();
   await poll(()=>page.evaluate(()=>navigator.clipboard.readText()),text=>text===cached);
   row.explicit_system_clipboard_copy=true;
   await page.getByRole('button',{name:'断开',exact:true}).click();
   const recording=await poll(()=>api('/recordings?connection_id='+ticket.connection_id),page=>page.items[0]?.state==='complete').then(page=>page.items[0]);
   const hasClipboard=await page.evaluate(async id=>{
     const response=await fetch('/api/v1/recordings/'+id+'/content',{credentials:'same-origin'});if(!response.ok)throw new Error('recording verification failed');
     const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true}),guacDecoder=new TextDecoder('utf-8',{fatal:true}),parser=new Guacamole.Parser(),images=new Set();let pending='',bad=false,terminal=false;
     parser.oninstruction=(opcode,args)=>{if(opcode==='clipboard'||opcode==='ack')bad=true;if(opcode==='img')images.add(args[0]);if((opcode==='blob'||opcode==='end')&&!images.has(args[0]))bad=true;if(opcode==='end')images.delete(args[0]);};
     for(;;){const {value,done}=await reader.read();pending+=decoder.decode(value,{stream:!done});let at;while((at=pending.indexOf('\n'))>=0){const line=JSON.parse(pending.slice(0,at));pending=pending.slice(at+1);if(line.type==='meta')terminal=line.stream_protocol==='bastion.ssh.v1';if(line.type==='output'){const data=Uint8Array.from(atob(line.data_base64),c=>c.charCodeAt(0));if(terminal){if(![1,2].includes(data[0]))bad=true;}else parser.receive(guacDecoder.decode(data,{stream:true}));}}if(done)break;}
     parser.receive(guacDecoder.decode());if(pending||images.size)throw new Error('unclean recording EOF');return bad;
   },recording.id);assert.equal(hasClipboard,false);row.clipboard_transfer_excluded_from_recording=true;
   await page.screenshot({path:path.join(output,profile.label+'.png')});result.profiles.push(row);console.log('Clipboard roundtrip passed: '+profile.label);
 }
 assert.deepEqual(errors,[]);result.status='passed-real-clipboard-components';
}catch(error){result.status='failed';result.error=error.message;await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});throw error;}
finally{await browser.close();await writeFile(path.join(output,'clipboard-evidence.json'),JSON.stringify(result,null,2)+'\n');}
console.log(JSON.stringify(result));
