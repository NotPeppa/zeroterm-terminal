// Supplemental matched-concurrency measurement; never starts another hour.
import {readFile,writeFile} from 'node:fs/promises';
process.env.BASTION_RELEASE_LOAD_LIBRARY='1';
const {Browser,transfer}=await import('./release_load_matched_library.mjs');
const fixture=JSON.parse(await readFile(process.env.BASTION_RELEASE_LOAD_FIXTURE,'utf8'));
const browser=new Browser(fixture.users[7]);await browser.login();
const label=`matched-proxy-${Date.now()}`;
const startedAt=new Date().toISOString();
const files=await Promise.all(fixture.files.map((file,index)=>transfer(browser,{...file,remote:`${file.remote}.${label}`},index)));
const phase=direction=>{const start=Math.min(...files.map(file=>file[`${direction}_started_ms`]));const end=Math.max(...files.map(file=>file[`${direction}_finished_ms`]));const bytes=files.reduce((sum,file)=>sum+file.bytes,0);return {total_bytes:bytes,first_started_monotonic_ms:start,last_finished_monotonic_ms:end,wall_seconds:(end-start)/1000,bytes_per_second:bytes*1000/(end-start)};};
const result={stage:'completed',started_at:startedAt,finished_at:new Date().toISOString(),concurrency:4,chunk_bytes:32768,source_archive_sha256:fixture.source_archive_sha256,binary_sha256:fixture.binary_sha256,files,upload:phase('upload'),download:phase('download'),method:'total bytes divided by first-start to last-finish wallclock, not sum of per-flow rates'};
await writeFile(`${fixture.workdir}/matched-proxy-baseline4.json`,JSON.stringify(result,null,2)+'\n',{mode:0o600});
console.log(JSON.stringify({stage:result.stage,upload:result.upload,download:result.download}));
