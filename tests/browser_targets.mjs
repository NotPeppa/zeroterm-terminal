import assert from 'node:assert/strict';

export async function selectBrowserTarget(page, assetId, accountId) {
  await page.evaluate(()=>{location.hash='#/assets';});
  await page.locator('.console-pane').waitFor({state:'hidden'});
  const issued=page.waitForResponse(row=>row.url().endsWith('/api/v1/sessions')&&row.request().method()==='POST');
  await page.evaluate(({assetId,accountId})=>{location.hash='#/console/'+encodeURIComponent(assetId)+'/'+encodeURIComponent(accountId);},{assetId,accountId});
  const response=await issued;
  const request=response.request().postDataJSON();assert.equal(request.asset_id,assetId);assert.equal(request.account_id,accountId);
  return response;
}
