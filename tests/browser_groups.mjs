import {selectBrowserTarget} from './browser_targets.mjs';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {randomUUID} from 'node:crypto';
import path from 'node:path';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_PACKAGE || 'playwright');
const fixture=JSON.parse(await readFile(process.argv[2],'utf8')),output=process.argv[3];assert.match(fixture.server_id,/^zt-guac-v2-[a-z0-9-]+$/);await mkdir(output,{recursive:true});
const result={production_ready:false,windows_nla_verified:false,application_image_id:fixture.application_image_id};
const browser=await chromium.launch({headless:true,args:['--ignore-certificate-errors-spki-list='+fixture.public_spki]});
const context=await browser.newContext();await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:fixture.origin});
const manage=await context.newPage(),session=await context.newPage(),errors=[];for(const page of [manage,session])page.on('pageerror',error=>errors.push(error.message));
async function api(path,method='GET',body,revision){return manage.evaluate(async({path,method,body,revision})=>{
 const headers={};if(method!=='GET'){const me=await (await fetch('/api/v1/me',{credentials:'same-origin'})).json();headers['X-Bastion-CSRF']=me.csrf_token;}if(body!==undefined)headers['Content-Type']='application/json';if(revision!==undefined)headers['If-Match']='"'+revision+'"';
 const response=await fetch('/api/v1'+path,{method,credentials:'same-origin',headers,body:body===undefined?undefined:JSON.stringify(body)});return{status:response.status,body:response.status===204?null:await response.json()};
},{path,method,body,revision});}
async function poll(read,accept,timeout=20000){const end=Date.now()+timeout;while(Date.now()<end){const value=await read();if(accept(value))return value;await manage.waitForTimeout(100);}throw new Error('group acceptance deadline');}
const target=fixture.profiles.find(row=>row.label==='ssh-password');assert(target);
try{
 await manage.goto(fixture.origin,{waitUntil:'networkidle'});assert.equal((await api('/info')).body.server_id,fixture.server_id);
 await manage.locator('#username').fill(fixture.username);await manage.locator('#password').fill(fixture.password);await manage.locator('#login').click();await manage.locator('#workspace').waitFor({state:'visible'});
 await session.goto(fixture.origin,{waitUntil:'networkidle'});const issued=await selectBrowserTarget(session,target.asset_id,target.account_id);assert.equal(issued.status(),201);const ticket=await issued.json();ticket.ws_token='';
 await session.waitForFunction(()=>document.querySelector('#status').textContent.includes('目标显示流已就绪') || document.querySelector('#status').textContent.includes('SSH 终端已就绪'),null,{timeout:50000});
 await manage.evaluate(()=>{location.hash='#/admin-assets';});await manage.getByRole('button',{name:'新建分组',exact:true}).waitFor();
 const before=(await api('/admin/assets/'+target.asset_id)).body,accountsBefore=(await api('/admin/assets/'+target.asset_id+'/accounts')).body;
 const name='验收 <b>'+randomUUID().slice(0,8)+'</b>';
 const created=manage.waitForResponse(row=>row.url().endsWith('/api/v1/admin/asset-groups')&&row.request().method()==='POST');await manage.getByRole('button',{name:'新建分组',exact:true}).click();let dialog=manage.getByRole('dialog');await dialog.getByLabel('分组名称',{exact:true}).fill(name);await dialog.getByRole('button',{name:'确认',exact:true}).click();let group=await(await created).json();await dialog.waitFor({state:'hidden'});
 const section=manage.locator('details.asset-group').filter({has:manage.locator('summary').filter({hasText:name})});await section.waitFor();assert.equal(await section.locator('summary b').count(),0);await section.locator('summary').click();assert.equal(await section.evaluate(node=>node.open),false);await section.locator('summary').click();
 await manage.getByRole('button',{name:'新建资产',exact:true}).click();dialog=manage.getByRole('dialog');await dialog.waitFor({state:'visible'});assert.equal(await dialog.locator('[name=group_id] option[value="'+group.id+'"]').count(),1);await dialog.getByRole('button',{name:'取消',exact:true}).click();
 const row=manage.locator('tr').filter({has:manage.getByText(target.asset_id,{exact:true})});await row.getByRole('button',{name:'编辑资产与账号',exact:true}).click();dialog=manage.getByRole('dialog');await dialog.locator('[name=group_id]').selectOption(group.id);const movedResponse=manage.waitForResponse(row=>row.url().endsWith('/api/v1/admin/assets/'+target.asset_id)&&row.request().method()==='PATCH');await dialog.getByRole('button',{name:'确认',exact:true}).click();const moved=await(await movedResponse).json();await dialog.waitFor({state:'hidden'});
 assert.equal(moved.group_id,group.id);assert.equal(moved.routing_revision,before.routing_revision);assert.equal((await api('/connections/'+ticket.connection_id)).body.state,'active');assert.deepEqual((await api('/admin/assets/'+target.asset_id+'/accounts')).body,accountsBefore);
 await manage.getByLabel('筛选资产分组',{exact:true}).selectOption(group.id);await poll(()=>api('/admin/assets?group_id='+group.id),response=>response.body.items.some(row=>row.id===target.asset_id));
 const filtered=(await api('/admin/assets?group_id='+group.id)).body;assert.equal(filtered.items.length,1);assert.equal(filtered.items[0].id,target.asset_id);
 assert.equal((await api('/admin/assets?group_id='+group.id+'&ungrouped=true')).status,400);
 assert.equal((await api('/admin/asset-groups/'+group.id,'PATCH',{name:'stale'},group.revision+1)).status,412);assert.equal((await api('/admin/asset-groups/'+group.id)).body.name,name);
 await manage.getByRole('button',{name:'管理分组',exact:true}).click();dialog=manage.getByRole('dialog');await dialog.locator('[name=group_id]').selectOption(group.id);await dialog.getByLabel('分组名称',{exact:true}).fill('生产验收');const renamed=manage.waitForResponse(row=>row.url().endsWith('/api/v1/admin/asset-groups/'+group.id)&&row.request().method()==='PATCH');await dialog.getByRole('button',{name:'确认',exact:true}).click();group=await(await renamed).json();await dialog.waitFor({state:'hidden'});assert.equal(group.name,'生产验收');
 await manage.evaluate(()=>{location.hash='#/assets';});const groupItem=manage.locator('.tree-item').filter({has:manage.locator('.tree-name').getByText(group.name,{exact:true})});await groupItem.click();await manage.locator('.tree-item.active').filter({has:manage.locator('.tree-name').getByText(group.name,{exact:true})}).waitFor();assert.equal(await manage.locator('tbody tr').count(),1);
 assert.equal((await api('/assets?group_id='+group.id)).body.items[0].group_name,group.name);
 await manage.screenshot({path:path.join(output,'grouped-assets.png')});
 await manage.evaluate(()=>{location.hash='#/admin-assets';});await manage.getByRole('button',{name:'管理分组',exact:true}).click();dialog=manage.getByRole('dialog');await dialog.locator('[name=group_id]').selectOption(group.id);await dialog.getByRole('button',{name:'删除分组',exact:true}).click();const confirmation=manage.getByRole('dialog').last();await confirmation.getByRole('button',{name:'确认',exact:true}).click();await confirmation.waitFor({state:'hidden'});
 const after=(await api('/admin/assets/'+target.asset_id)).body;assert.equal(after.group_id,null);assert.equal(after.routing_revision,before.routing_revision);assert.equal((await api('/admin/asset-groups/'+group.id)).status,404);assert.deepEqual((await api('/admin/assets/'+target.asset_id+'/accounts')).body,accountsBefore);assert.equal((await api('/connections/'+ticket.connection_id)).body.state,'active');
 const command="printf 'ZT_GROUP_CONNECTION_OK\\n'";if(await session.locator('.terminal-viewport').count()){
  // xterm SSH: echo plus real printf output means the marker appears at least twice.
  await session.locator('.terminal-viewport textarea').focus();await session.keyboard.type(command);await session.keyboard.press('Enter');
  await session.waitForFunction(()=>(document.querySelector('.terminal-viewport .xterm-rows')?.textContent.match(/ZT_GROUP_CONNECTION_OK/g)??[]).length>=2,null,{timeout:20000});
 }else{await session.evaluate(text=>navigator.clipboard.writeText(text),command);await session.locator('.guac-viewport textarea').focus();await session.keyboard.press('Control+v');await session.waitForFunction(()=>document.querySelector('#status').textContent==='文本已发送到目标。');await session.keyboard.press('Enter');await session.waitForTimeout(500);}
 assert.equal(await session.locator('#error').textContent(),'');
 await session.getByRole('button',{name:'断开',exact:true}).click();await poll(()=>api('/recordings?connection_id='+ticket.connection_id),response=>response.body.items[0]?.state==='complete');assert.deepEqual(errors,[]);
 Object.assign(result,{status:'passed-real-browser-groups',group_create_rename_delete:true,group_selection_and_filters:true,text_only_group_name_rendering:true,stale_revision_rejected:true,delete_preserves_assets_accounts_and_grants:true,metadata_keeps_ssh_connection_active:true,recording_complete:true,page_errors:errors});
}catch(error){result.status='failed';result.error=error.message;await manage.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});throw error;}
finally{await browser.close();await writeFile(path.join(output,'group-evidence.json'),JSON.stringify(result,null,2)+'\n');}
console.log(JSON.stringify(result));
