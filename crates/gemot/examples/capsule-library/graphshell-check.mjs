// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

import { chromium } from 'playwright';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import assert from 'node:assert/strict';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
const [url, output] = process.argv.slice(2);
if (!url || !output) throw new Error('Pass graphshell.html URL and the proof run directory');
const root = resolve(output);
await mkdir(root, { recursive: true });
const browser = await chromium.launch({ channel: 'chrome', headless: false, args: ['--enable-unsafe-webgpu'] });
const context = await browser.newContext({ viewport: { width: 1280, height: 960 } });
const page = await context.newPage();
const errors = [];
page.on('pageerror', error => errors.push(String(error)));
page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
await page.addInitScript(() => {
  window.graphshellAdapters = [];
  if (navigator.gpu) {
    const original = navigator.gpu.requestAdapter.bind(navigator.gpu);
    navigator.gpu.requestAdapter = async options => {
      const adapter = await original(options);
      if (adapter) window.graphshellAdapters.push({
        options, vendor: adapter.info.vendor, architecture: adapter.info.architecture,
        device: adapter.info.device, description: adapter.info.description,
        isFallbackAdapter: adapter.info.isFallbackAdapter ?? adapter.isFallbackAdapter ?? null,
      });
      return adapter;
    };
  }
});
const receipt = { host: 'graphshell-web retained tree', browser: browser.version(), checks: {}, captures: [] };
const wait = (predicate, arg = null) => page.waitForFunction(predicate, arg, { timeout: 60000 });
const state = () => page.evaluate(() => window.graphshellApplet.receipt());
const localKeys = () => page.evaluate(async () => {
  const request = indexedDB.open('graphshell-capsule-applets-v1');
  const db = await new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
  try {
    const request = db.transaction('muniment').objectStore('muniment').getAllKeys();
    return await new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
  } finally { db.close(); }
});
const capture = async name => {
  // Allow the presenter to finish a frame after the retained tree changes.
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await page.screenshot({ path: join(root, name), fullPage: false });
  const pixels = await promisify(execFile)(process.env.CAPSULE_PYTHON || 'python3', ['-c',
    "from PIL import Image; import json,sys; im=Image.open(sys.argv[1]).convert('RGB'); p=list(im.getdata()); print(json.dumps({'colors':len(set(p)), 'bright_pixels':sum(min(c)>100 for c in p)}))", join(root, name)]);
  const visual = JSON.parse(pixels.stdout);
  assert.ok(visual.colors > 32 && visual.bright_pixels > 500, 'Blank or unpainted Graphshell capture: ' + name);
  receipt.captures.push(name);
  (receipt.pixels ??= {})[name] = visual;
};
// Cambium's mirror is an accessibility tree; actual pointer input hits the
// painted canvas at those same retained rectangles.
const click = async locator => {
  const box = await locator.boundingBox();
  assert.ok(box && box.width && box.height, 'No retained control rectangle');
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
};
try {
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await wait(() => document.querySelector('graphshell-tree').dataset.appletReady === 'true');
  assert.deepEqual((await state()).grants, []);
  assert.equal((await state()).transport.starts, 0);
  receipt.checks.explicit_review = true;
  await assert.rejects(page.evaluate(async () => {
    const { Runtime } = await import('./runtime.mjs');
    const fixture = await (await fetch('./fixture.json')).json();
    const runtime = new Runtime();
    try {
      await runtime.call('init', { pack: fixture.app, component_hash: fixture.component_hash,
        entries: fixture.catalogue.entries, grants: ['power:capsule-view'],
        bindings_hash: '0'.repeat(64) }, 15000);
    } finally { runtime.close(); }
  }), /derivation/);
  receipt.checks.unpinned_browser_derivation_refused = true;
  await capture('graphshell-review.png');
  await click(page.getByRole('button', { name: 'Run catalogue and reader', exact: true }));
  await wait(() => window.graphshellApplet.receipt().projection?.length === 2);
  const native = JSON.parse(await readFile(join(root, 'native.json'), 'utf8'));
  const first = await state();
  assert.deepEqual(first.projection, native.browse);
  receipt.checks.native_browse_parity = true;
  await click(page.getByRole('textbox', { name: 'Search capsules' }));
  await page.keyboard.type('garden');
  await click(page.getByRole('button', { name: 'Search', exact: true }));
  await wait(() => window.graphshellApplet.receipt().projection?.length === 1);
  assert.deepEqual((await state()).projection, native.search);
  receipt.checks.native_search_parity = true;
  await click(page.getByRole('button', { name: "Open Alice's garden", exact: true }));
  await wait(() => window.graphshellApplet.receipt().opened?.body.includes('pear tree'));
  assert.equal((await state()).kept, false);
  const keys = await localKeys();
  assert.deepEqual(keys, []);
  receipt.checks.read_without_retention = true;
  await capture('graphshell-reader.png');
  const firstReading = (await state()).selected_reading;
  await page.evaluate(() => {
    window.originalCapsulePut = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function () { throw new DOMException('controlled storage refusal', 'QuotaExceededError'); };
  });
  await click(page.getByRole('button', { name: `Keep revision in reading ${firstReading}`, exact: true }));
  await wait(() => window.graphshellApplet.receipt().refusals.some(refusal => refusal.tag === 'retention'));
  assert.equal((await state()).running, true);
  assert.equal((await state()).kept, false);
  assert.deepEqual(await localKeys(), []);
  await page.evaluate(() => { IDBObjectStore.prototype.put = window.originalCapsulePut; });
  receipt.checks.retention_failure_preserves_execution_and_retry = true;
  await click(page.getByRole('button', { name: `Keep revision in reading ${firstReading}`, exact: true }));
  await wait(() => window.graphshellApplet.receipt().kept);
  receipt.checks.muniment_retention = true;

  await click(page.getByRole('button', { name: "Open another reading of Alice's garden", exact: true }));
  await wait(() => window.graphshellApplet.receipt().readings?.length === 2);
  const copies = (await state()).readings;
  assert.notEqual(copies[0].id, copies[1].id);
  assert.equal(copies[0].opened.entry.revision, copies[1].opened.entry.revision);
  assert.equal(copies[0].opened.body, copies[1].opened.body);
  assert.ok(copies.every(reading => reading.kept));
  receipt.checks.independent_accesses_same_revision = true;
  await click(page.getByRole('button', { name: 'Clear reading selection', exact: true }));
  await wait(() => window.graphshellApplet.receipt().selected_reading == null);
  assert.equal((await state()).readings.length, 2);
  assert.ok((await state()).readings.every(reading => reading.kept));
  await click(page.getByRole('button', { name: `Close reading ${firstReading}`, exact: true }));
  await wait(() => window.graphshellApplet.receipt().readings?.length === 1);
  const survivor = copies[1].id;
  assert.equal((await state()).readings[0].id, survivor);
  await assert.rejects(page.evaluate(id => window.graphshellWasm.applet_select_reading(id), firstReading));
  await click(page.getByRole('button', { name: `Select reading ${survivor}`, exact: true }));
  await wait(id => window.graphshellApplet.receipt().selected_reading === id, survivor);
  receipt.checks.selection_and_close_preserve_other_reading = true;

  await click(page.getByRole('textbox', { name: 'Search capsules' }));
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.press('Backspace');
  await click(page.getByRole('button', { name: 'Search', exact: true }));
  await wait(() => window.graphshellApplet.receipt().projection?.length === 2);
  assert.equal((await state()).readings[0].id, survivor);
  await click(page.getByRole('button', { name: "Open Bob's listening room", exact: true }));
  await wait(() => window.graphshellApplet.receipt().readings?.length === 2);
  const bob = (await state()).selected_reading;
  assert.equal((await state()).readings.find(reading => reading.id === survivor).kept, true);
  assert.equal((await state()).readings.find(reading => reading.id === bob).kept, false);
  receipt.checks.catalogue_filter_preserves_readings = true;
  await capture('graphshell-readings.png');
  await page.setViewportSize({ width: 520, height: 1120 });
  await page.waitForTimeout(200);
  await page.mouse.move(450, 700);
  await page.mouse.wheel(0, 500);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  const narrowClose = await page.getByRole('button', { name: `Close reading ${bob}`, exact: true }).boundingBox();
  receipt.narrow_control = { viewport: page.viewportSize(), close_reading: bob, bounds: narrowClose };
  assert.ok(narrowClose && narrowClose.x >= 0 && narrowClose.x + narrowClose.width <= 520
    && narrowClose.y >= 0 && narrowClose.y + narrowClose.height <= 1120, 'Narrow reading controls must remain reachable by scrolling');
  await click(page.getByRole('button', { name: `Select reading ${survivor}`, exact: true }));
  await wait(id => window.graphshellApplet.receipt().selected_reading === id, survivor);
  receipt.checks.narrow_reading_controls_reachable = true;
  await capture('graphshell-readings-narrow.png');
  await page.setViewportSize({ width: 1280, height: 960 });
  await page.waitForTimeout(200);
  await click(page.getByRole('button', { name: `Close reading ${bob}`, exact: true }));
  await wait(id => window.graphshellApplet.receipt().selected_reading === id, survivor);
  assert.equal((await state()).kept, true);
  await assert.rejects(page.evaluate(id => window.graphshellWasm.applet_close_reading(id), bob));
  const stored = await localKeys();
  assert.equal(stored.length, 1);
  assert.ok(String(stored[0]).endsWith(copies[0].opened.entry.revision));
  receipt.checks.per_revision_retention_survives_other_close = true;

  const address = (await state()).opened.entry.url;
  for (let i = 1; i < 8; ++i) await page.evaluate(url => window.graphshellApplet.turn('open', JSON.stringify({url})), address);
  assert.equal((await state()).readings.length, 8);
  await page.evaluate(url => window.graphshellApplet.turn('open', JSON.stringify({url})), address);
  assert.equal((await state()).readings.length, 8);
  assert.equal((await state()).running, true);
  assert.equal((await state()).refusals.at(-1).tag, 'denied');
  for (const reading of (await state()).readings) {
    if (reading.id !== survivor) await page.evaluate(id => window.graphshellWasm.applet_close_reading(id), reading.id);
  }
  receipt.checks.reading_limit_preserves_active_host = true;

  await page.evaluate(() => window.graphshellApplet.turn('probe'));
  const refused = (await state()).refusals.map(r => r.tag);
  assert.deepEqual(refused.slice(-4), ['denied', 'denied', 'malformed', 'unknown']);
  receipt.checks.typed_refusals = true;
  // Send an already-returned navigation as though the worker were delayed.
  const queued = await state();
  const urlToOpen = queued.opened.entry.url;
  await click(page.getByRole('button', { name: 'Revoke navigation', exact: true }));
  await wait(() => !window.graphshellApplet.receipt().grants.includes('power:navigate'));
  await page.evaluate(({ generation, url }) => {
    window.graphshellWasm.applet_apply_turn(generation, JSON.stringify({
      actions: [{ name:'open-address', payload:{url} }], logs:[], refusals:[],
    }));
  }, { generation: queued.generation, url: urlToOpen });
  assert.equal((await state()).refusals.at(-1).tag, 'denied');
  await assert.rejects(page.evaluate(({ generation, url }) => window.graphshellWasm.applet_open_body(
    generation, url, new TextEncoder().encode('# late body'), false),
  { generation: queued.generation, url: urlToOpen }));
  receipt.checks.queued_action_and_body_revocation = true;

  // A rejected replacement leaves the current verified mount untouched.
  await assert.rejects(page.evaluate(async () => {
    const invalid = structuredClone(window.graphshellConfig);
    invalid.disclosure.capsules[0].entry.author = 'different author';
    await window.graphshellApplet.review(invalid);
  }));
  assert.equal((await state()).generation, queued.generation);
  receipt.checks.failed_replacement_preserves_mount = true;
  await page.evaluate(() => window.graphshellApplet.review(window.graphshellConfig));
  await assert.rejects(page.evaluate(({ generation }) => window.graphshellWasm.applet_apply_turn(
    generation, JSON.stringify({ actions:[], logs:[], refusals:[] })),
  { generation: queued.generation }));
  receipt.checks.stale_turn_refused = true;
  await click(page.getByRole('button', { name: 'Run catalogue and reader', exact: true }));
  await wait(() => window.graphshellApplet.receipt().projection?.length === 2);
  await assert.rejects(page.evaluate(() => window.graphshellApplet.turn('spin')), /time limit/);
  assert.equal((await state()).running, false);
  assert.equal((await state()).transport.interrupted, 1);
  receipt.checks.runaway_interrupted = true;
  await click(page.getByRole('button', { name: 'Run catalogue only', exact: true }));
  await wait(() => window.graphshellApplet.receipt().projection?.length === 2);
  assert.deepEqual((await state()).grants, ['power:capsule-view']);
  receipt.checks.fresh_instance_after_interruption = true;

  // The normal page reload opens a fresh host; retained data remains local.
  await page.reload({ waitUntil: 'domcontentloaded' });
  await wait(() => document.querySelector('graphshell-tree').dataset.appletReady === 'true');
  await click(page.getByRole('button', { name: 'Run catalogue and reader', exact: true }));
  await wait(() => window.graphshellApplet.receipt().projection?.length === 2);
  await context.setOffline(true);
  await click(page.getByRole('button', { name: "Open Alice's garden", exact: true }));
  await wait(() => window.graphshellApplet.receipt().opened?.body.includes('pear tree'));
  assert.equal((await state()).kept, true);
  receipt.checks.reopened_offline_muniment_read = true;
  await context.setOffline(false);
  await capture('graphshell-reopened.png');
  receipt.state = await state();
  receipt.adapters = await page.evaluate(() => window.graphshellAdapters);
  assert.ok(receipt.adapters.length > 0, 'No actual Graphshell GPU adapter request recorded');
  assert.ok(receipt.adapters.every(a => a.isFallbackAdapter !== true), 'Fallback adapter cannot qualify this presentation');
  receipt.page_errors = await page.evaluate(() => window.graphshellErrors);
  assert.deepEqual(receipt.page_errors, []);
  assert.deepEqual(errors, []);
  receipt.errors = errors;
  receipt.bindings = JSON.parse(await readFile(join(root, 'site', 'graphshell-bindings.json'), 'utf8'));
  assert.equal(receipt.state.component_hash, receipt.bindings.component_hash);
  await writeFile(join(root, 'graphshell.json'), JSON.stringify(receipt, null, 2));
  console.log('Graphshell retained applet checks passed; captures and receipt: ' + root);
} catch (error) {
  receipt.failure = String(error);
  receipt.adapters = await page.evaluate(() => window.graphshellAdapters);
  receipt.errors = errors;
  receipt.page_errors = await page.evaluate(() => window.graphshellErrors);
  await page.screenshot({ path: join(root, 'graphshell-failed.png'), fullPage: false });
  receipt.captures.push('graphshell-failed.png');
  await writeFile(join(root, 'graphshell-failed.json'), JSON.stringify(receipt, null, 2));
  throw error;
} finally { await browser.close(); }
