// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

// Real Chromium execution; no stubbed Wasm exports, fetch, crypto or IndexedDB.
// `node browser-check.mjs <served-site-url> <proof-root>`
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium } from 'playwright';

const [base, root] = process.argv.slice(2);
if (!base || !root) throw new Error('Requires served site URL and proof root');
const native = JSON.parse(await readFile(join(root, 'native.json'), 'utf8'));
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1200, height: 980 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.goto(base);
  await page.waitForFunction(() => window.__capsuleProof?.ready || window.__capsuleProof?.error);
  assert.equal(await page.evaluate(() => window.__capsuleProof.error), undefined);
  assert.equal(await page.evaluate(() => window.__capsuleProof.component_hash), null, 'No component execution before review');
  const negative = await page.evaluate(async () => {
    const { verifyPack, verifyPart, fetchBytes } = await import('./verify.mjs');
    const fixture = await (await fetch('fixture.json')).json();
    const results = {};
    const broken = structuredClone(fixture.app); broken.manifest.requested_scopes.push('power:session');
    try { await verifyPack(broken); results.widened_ask_refused = false; } catch { results.widened_ask_refused = true; }
    const original = await fetchBytes('library.wasm'); const corrupt = original.slice(); corrupt[100] ^= 1;
    try { verifyPart(fixture.app.manifest.parts[0], corrupt); results.changed_component_refused = false; } catch { results.changed_component_refused = true; }
    try { await verifyPack(fixture.capsule_packs[0], fixture.capsule_packs[1].manifest.author); results.foreign_contributor_refused = false; }
    catch { results.foreign_contributor_refused = true; }
    return results;
  });
  assert.ok(Object.values(negative).every(Boolean));
  await page.locator('#grant-view').uncheck();
  await page.locator('#start').click();
  await page.waitForFunction(() => window.__capsuleProof.logs.some(l => l.includes('missing power:capsule-view')) || window.__capsuleProof.error);
  assert.equal(await page.evaluate(() => window.__capsuleProof.error), undefined);
  const missing_capability_reported = await page.evaluate(() => window.__capsuleProof.logs.some(l => l.includes('missing power:capsule-view')));
  await page.locator('#stop').click();
  await page.locator('#grant-view').check();
  await page.locator('#start').click();
  await page.waitForFunction(() => document.querySelectorAll('#entries li').length === 2 || window.__capsuleProof.error);
  assert.equal(await page.evaluate(() => window.__capsuleProof.error), undefined);
  const browse = await page.evaluate(() => window.__capsuleProof.events.filter(e => e.kind === 'catalogue').at(-1).actions[0].payload);
  assert.deepEqual(browse, native.browse);
  await page.locator('#search').fill('garden');
  await page.waitForFunction(() => document.querySelectorAll('#entries li').length === 1);
  const search = await page.evaluate(() => window.__capsuleProof.events.filter(e => e.kind === 'catalogue').at(-1).actions[0].payload);
  assert.deepEqual(search, native.search);
  await page.locator('#entries button').click();
  await page.waitForFunction(() => document.querySelector('#body').textContent.includes('pear tree') || window.__capsuleProof.error);
  assert.equal(await page.evaluate(() => window.__capsuleProof.error), undefined);
  assert.equal(await page.evaluate(async () => {
    const request = indexedDB.open(`mere-capsule-proof-${(await (await fetch('fixture.json')).json()).moot}`, 1);
    const db = await new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    const count = await new Promise((resolve, reject) => {
      const req = db.transaction('capsules').objectStore('capsules').count();
      req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
    });
    db.close(); return count;
  }), 0, 'Reading alone must not persist a capsule');
  await page.locator('#keep-addresses').click();
  await page.waitForFunction(() => window.__capsuleProof.addresses_kept === true);
  assert.equal(await page.locator('#storage').textContent(), 'No capsule files saved on this device.');
  await page.locator('#keep').click();
  await page.waitForFunction(() => window.__capsuleProof.saved.length === 1);
  // Fresh page reopen proves persistence; an offline read then uses real IDB.
  await page.reload();
  await page.waitForFunction(() => window.__capsuleProof?.ready);
  assert.equal(await page.locator('#storage').textContent(), '1 kept capsule revision on this device.');
  await page.locator('#start').click();
  await page.waitForFunction(() => document.querySelectorAll('#entries li').length === 2);
  await page.locator('#entries button').first().click();
  await page.waitForFunction(() => !document.querySelector('#retained').disabled);
  await context.setOffline(true);
  await page.locator('#retained').click();
  await page.waitForFunction(() => !!window.__capsuleProof.offline_read_hash);
  const offline_read_hash = await page.evaluate(() => window.__capsuleProof.offline_read_hash);
  await context.setOffline(false);
  await page.locator('summary').click();
  await page.locator('#probe').click();
  await page.waitForFunction(() => window.__capsuleProof.refusals.length === 4);
  const refusals = await page.evaluate(() => window.__capsuleProof.refusals);
  assert.deepEqual(refusals.map(r => r.tag), ['denied', 'denied', 'malformed', 'unknown']);
  await page.locator('#grant-nav').uncheck();
  await page.waitForFunction(() => window.__capsuleProof.revoked?.includes('power:navigate'));
  await page.locator('#probe').click();
  await page.waitForFunction(() => window.__capsuleProof.refusals.length === 8);
  const revocation = await page.evaluate(() => window.__capsuleProof.refusals.slice(4));
  assert.deepEqual(revocation.map(r => r.tag), ['denied', 'denied', 'denied', 'unknown']);
  assert.ok(await page.locator('#entries button').first().isDisabled());
  await page.locator('#spin').click();
  await page.waitForFunction(() => window.__capsuleProof.runaway_interrupted === true, null, { timeout: 10000 });
  await page.locator('#grant-nav').check();
  const turns_before_restart = await page.evaluate(() => window.__capsuleProof.events.filter(e => e.kind === 'catalogue').length);
  await page.locator('#start').click();
  await page.waitForFunction(count => window.__capsuleProof.events.filter(e => e.kind === 'catalogue').length > count, turns_before_restart);
  await page.waitForFunction(() => document.querySelectorAll('#entries li').length === 2);
  await page.locator('summary').click();
  await page.screenshot({ path: join(root, 'browser.png'), fullPage: true });
  assert.deepEqual(errors, []);
  const receipt = { browser: browser.version(), actual_component_hash: await page.evaluate(() => window.__capsuleProof.component_hash),
    native_browser_browse_equal: true, native_browser_search_equal: true, browse, search, ...negative,
    missing_capability_reported, no_execution_before_review: true, reading_did_not_persist: true,
    address_only_retention_passed: true, reopened_idb_and_offline_read_passed: true, offline_read_hash,
    refusals, grant_revocation_refused: true, runaway_interrupted_and_host_recovered: true,
    scope: 'Real Chromium and real IndexedDB on one machine; host-page offline reload and Graphshell mounting are not qualified.' };
  await writeFile(join(root, 'browser.json'), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt, null, 2));
} finally { await browser.close(); }
