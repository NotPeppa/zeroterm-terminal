// Supplemental real revocation probe while the original70-shell hour keeps running.
// Reads only the existing0600 owned fixture; does not replace the full-hour result.
import {readFile,writeFile} from 'node:fs/promises';
process.env.BASTION_RELEASE_LOAD_LIBRARY='1';
const {Browser,revokeProbe,quantiles}=await import('./release_load.mjs');
const fixture=JSON.parse(await readFile(process.env.BASTION_RELEASE_LOAD_FIXTURE,'utf8'));
const result={started_at:new Date().toISOString(),expected_existing_shells:70,samples_ms:[],state:'running'};
try{
  for(let index=8;index<13;index++){
    const browser=new Browser(fixture.users[index]);await browser.login();
    result.samples_ms.push(await revokeProbe(browser,index));
  }
  result.state='completed';result.revocation=quantiles(result.samples_ms);result.finished_at=new Date().toISOString();
}catch(error){result.state='failed';result.error={name:error.name,message:error.message};process.exitCode=1;}
await writeFile(`${fixture.workdir}/revoke-under-load.json`,JSON.stringify(result,null,2)+'\n',{mode:0o600});
console.log(JSON.stringify({state:result.state,revocation:result.revocation}));
