// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
import { digest, verifyPack, verifyPart, fetchBytes } from './verify.mjs';
import { Runtime } from './runtime.mjs';

const $ = id => document.getElementById(id);
const receipt = { host: 'browser example', events: [], refusals: [], logs: [], saved: [], component_hash: null };
window.__capsuleProof = receipt;
let fixture;
let runtime;
let grants = [];
let current;
let currentBytes;
let token = 0;
function notice(text) { $('notice').textContent = text; }
function diagnostics() { $('diagnostics').textContent = JSON.stringify(receipt, null, 2); }
function guard(operation) { return async (...args) => { try { await operation(...args); } catch (error) { notice(String(error)); receipt.error = String(error); diagnostics(); } }; }


function showEntries(entries) {
  $('entries').replaceChildren();
  $('count').textContent = `${entries.length} shared address${entries.length === 1 ? '' : 'es'}`;
  for (const entry of entries) {
    const li = document.createElement('li');
    const title = document.createElement('h3'); title.textContent = entry.title;
    const info = document.createElement('small'); info.textContent = `Author ${entry.author.slice(0, 10)}… · ${entry.bytes} bytes`;
    const open = document.createElement('button'); open.textContent = 'Open capsule'; open.disabled = !grants.includes('power:navigate');
    open.addEventListener('click', guard(() => turn('open', JSON.stringify({ url: entry.url }))));
    li.append(title, info, open); $('entries').append(li);
  }
}

async function apply(result, kind) {
  receipt.events.push({ kind, actions: result.actions });
  receipt.refusals.push(...result.refusals);
  receipt.logs.push(...result.logs);
  for (const action of result.actions) {
    // Check again when lowering, after the guest turn; an emitted action
    // cannot outlive a revoked local grant or widen the disclosed addresses.
    if (action.name === 'capsule-library-view' && grants.includes('power:capsule-view')) showEntries(action.payload);
    if (action.name === 'open-address' && grants.includes('power:navigate')) await openAddress(action.payload.url);
  }
  diagnostics();
}
async function turn(kind, payload) {
  if (!runtime) throw new Error('Run the applet first');
  await apply(await runtime.call('event', { kind, payload }), kind);
}
async function catalogue() { await turn('catalogue', JSON.stringify({ ...fixture.catalogue, query: $('search').value })); }

function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(`mere-capsule-proof-${fixture.moot}`, 1);
    request.onupgradeneeded = () => { request.result.createObjectStore('capsules'); request.result.createObjectStore('collections'); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function stored(name, key, value) {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(name, value === undefined ? 'readonly' : 'readwrite');
      const request = value === undefined ? transaction.objectStore(name).get(key) : transaction.objectStore(name).put(value, key);
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error || new Error('Storage aborted'));
    });
  } finally { db.close(); }
}
async function storageStatus() {
  const db = await database();
  try {
    const count = await new Promise((resolve, reject) => {
      const request = db.transaction('capsules').objectStore('capsules').count();
      request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
    $('storage').textContent = count ? `${count} kept capsule revision${count === 1 ? '' : 's'} on this device.` : 'No capsule files saved on this device.';
  } finally { db.close(); }
}
function display(entry, bytes, kept) {
  $('reader-title').textContent = entry.title;
  $('reader-placeholder').hidden = true;
  $('reader-info').textContent = `Author ${entry.author.slice(0, 12)}… · revision ${entry.revision.slice(0, 12)}…${kept ? ' · kept on this device' : ''}`;
  $('body').textContent = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  $('keep').disabled = kept; $('retained').disabled = !kept;
}
async function openAddress(url) {
  const mine = ++token;
  const entry = fixture.catalogue.entries.find(e => e.url === url);
  if (!entry) throw new Error('Address outside disclosed catalogue');
  const saved = await stored('capsules', entry.revision);
  const packBytes = saved ? new Uint8Array(saved.packBytes) : await fetchBytes(`capsules/${entry.revision}.json`);
  if (digest(packBytes) !== entry.revision) throw new Error('Capsule pack address mismatch');
  const pack = JSON.parse(new TextDecoder().decode(packBytes));
  await verifyPack(pack, entry.author);
  const bytes = saved ? new Uint8Array(saved.bytes) : await fetchBytes(`capsules/${entry.revision}.gmi`);
  verifyPart(pack.manifest.parts[0], bytes);
  if (mine !== token) return;
  current = { entry, pack, packBytes }; currentBytes = bytes;
  display(entry, bytes, !!saved);
  receipt.last_opened = entry.revision;
  receipt.last_content_hash = digest(bytes);
  notice(saved ? 'Opened your kept revision.' : 'Verified this revision. Reading it has not saved a capsule file.');
}

$('start').addEventListener('click', guard(async () => {
  runtime?.close();
  grants = [...($('grant-view').checked ? ['power:capsule-view'] : []), ...($('grant-nav').checked ? ['power:navigate'] : [])];
  receipt.review = { confirmed: true, grants: [...grants] };
  runtime = new Runtime();
  const result = await runtime.call('init', { pack: fixture.app, component_hash: fixture.component_hash,
    entries: fixture.catalogue.entries, grants, bindings_hash: fixture.browser_bindings_hash }, 15000);
  receipt.component_hash = result.value.component_hash;
  receipt.jco = result.value.jco;
  await apply(result, 'activate');
  $('stop').disabled = false; $('search').disabled = !grants.includes('power:capsule-view');
  $('probe').disabled = false; $('spin').disabled = false;
  await catalogue();
  notice(grants.includes('power:capsule-view') ? 'Applet running. Capsules remain independently signed.' : 'Applet reported a missing catalogue capability. Change the review to run it with that capability.');
}));
$('stop').addEventListener('click', guard(async () => {
  if (runtime) { await apply(await runtime.call('stop'), 'deactivate'); runtime.close(); runtime = undefined; }
  grants = []; $('stop').disabled = true; $('search').disabled = true; $('probe').disabled = true; $('spin').disabled = true;
  showEntries([]); notice('Applet stopped. Your kept revisions remain on this device.');
}));
for (const [id, cap] of [['grant-view', 'power:capsule-view'], ['grant-nav', 'power:navigate']]) {
  $(id).addEventListener('change', guard(async () => {
    if (runtime && !$(id).checked) {
      grants = grants.filter(g => g !== cap);
      await runtime.call('grants', grants);
      receipt.revoked = [...(receipt.revoked || []), cap];
      if (cap === 'power:capsule-view') { showEntries([]); $('search').disabled = true; } else await catalogue();
      notice('Revoked for this running applet. A new grant requires Run applet.'); diagnostics();
    }
  }));
}
$('search').addEventListener('input', guard(catalogue));
$('keep').addEventListener('click', guard(async () => {
  if (!current || !currentBytes) throw new Error('Open a capsule first');
  const { entry, packBytes } = current;
  await stored('capsules', entry.revision, { bytes: currentBytes, packBytes, entry });
  $('keep').disabled = true; $('retained').disabled = false;
  receipt.saved.push(entry.revision);
  await storageStatus();
  notice('Saved this exact revision. Its author and community reference are unchanged.'); diagnostics();
}));
$('retained').addEventListener('click', guard(async () => {
  if (!current) throw new Error('Open a capsule first');
  const saved = await stored('capsules', current.entry.revision);
  if (!saved) throw new Error('No retained revision');
  const packBytes = new Uint8Array(saved.packBytes);
  if (digest(packBytes) !== saved.entry.revision) throw new Error('Retained pack address mismatch');
  const pack = JSON.parse(new TextDecoder().decode(packBytes));
  await verifyPack(pack, saved.entry.author);
  const bytes = new Uint8Array(saved.bytes); verifyPart(pack.manifest.parts[0], bytes);
  display(saved.entry, bytes, true); receipt.offline_read_hash = digest(bytes);
  notice('Read your kept revision from local storage.'); diagnostics();
}));
$('keep-addresses').addEventListener('click', guard(async () => {
  await stored('collections', 'selected', { entries: fixture.catalogue.entries, collection: fixture.collection });
  receipt.addresses_kept = true; notice('Kept the collection’s addresses. Capsule and applet payloads were not added to storage.'); diagnostics();
}));
$('probe').addEventListener('click', guard(async () => { await turn('probe', ''); notice('Action checks completed; inspect the typed refusals below.'); }));
$('spin').addEventListener('click', guard(async () => {
  try { await turn('spin', ''); throw new Error('Runaway unexpectedly returned'); }
  catch (error) {
    if (!String(error).includes('time limit')) throw error;
    receipt.runaway_interrupted = true; runtime = undefined; grants = [];
    $('search').disabled = true; $('stop').disabled = true; $('probe').disabled = true; $('spin').disabled = true;
    notice('Interrupted the runaway applet. This host is still responsive; Run applet starts a fresh instance.'); diagnostics();
  }
}));

await guard(async () => {
  const response = await fetch('fixture.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Host fixture unavailable');
  fixture = await response.json();
  await verifyPack(fixture.app);
  for (const pack of fixture.capsule_packs) await verifyPack(pack);
  receipt.app_signature_verified = true;
  receipt.publisher_exited = fixture.publisher_exited;
  receipt.catalogue = fixture.catalogue;
  await storageStatus();
  $('signature').textContent = `Verified author ${fixture.app.manifest.author.slice(0, 10)}… · asks for two powers`;
  $('status').textContent = 'Publisher offline · retained by a member';
  $('start').disabled = typeof WebAssembly !== 'object' || typeof Worker !== 'function';
  $('keep-addresses').disabled = false;
  if ($('start').disabled) notice('This host cannot run the component. Its shared addresses can still be kept.');
  receipt.ready = true; diagnostics();
})();
