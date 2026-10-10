// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

import { readFile, writeFile, mkdir, cp, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, join, dirname } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { blake3 } from '@noble/hashes/blake3.js';

if (!process.argv[2] || !process.argv[3]) throw new Error('Pass the proof site and built graphshell_web.wasm');
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../../../..');
const site = resolve(process.argv[2]);
const digest = bytes => Buffer.from(blake3(bytes)).toString('hex');
const fixture = JSON.parse(await readFile(join(site, 'fixture.json'), 'utf8'));
const capsules = [];
for (const entry of fixture.catalogue.entries) {
  const pack_bytes = await readFile(join(site, 'capsules', entry.revision + '.json'));
  if (digest(pack_bytes) !== entry.revision) throw new Error('Selected pack address mismatch');
  capsules.push({ entry, pack_bytes: [...pack_bytes] });
}
const disclosure = {
  moot: fixture.moot,
  collection: Buffer.from(fixture.collection.collection.collection_id).toString('hex'),
  revision: digest(new TextEncoder().encode(JSON.stringify(fixture.collection))),
  capsules,
};
const config = { baseURL: './', packURL: 'app-pack.json', packHash: fixture.app_pack_hash,
  bindingsHash: digest(await readFile(join(site, 'bindings.json'))), disclosure };
await writeFile(join(site, 'graphshell-config.json'), JSON.stringify(config, null, 2));
await mkdir(join(site, 'graphshell'), { recursive: true });
await promisify(execFile)('wasm-bindgen', [resolve(process.argv[3]), '--target', 'web',
  '--remove-name-section', '--remove-producers-section',
  '--out-dir', join(site, 'graphshell'), '--out-name', 'graphshell_web']);
const sources = {};
for (const name of ['graphshell-entry.mjs', 'graphshell.html']) {
  await cp(join(here, name), join(site, name));
  sources[name] = digest(await readFile(join(here, name)));
}
await cp(join(root, 'ports/graphshell/web/applets/host.mjs'), join(site, 'host.mjs'));
sources['host.mjs'] = digest(await readFile(join(root, 'ports/graphshell/web/applets/host.mjs')));
await cp(join(root, 'ports/graphshell/web/styles.css'), join(site, 'styles.css'));
for (const path of [
  'ports/graphshell/src/capsule_applet.rs', 'ports/graphshell/src/web_tree.rs',
  'ports/graphshell/src/web_tree/applet.rs', 'ports/graphshell/Cargo.toml',
  'ports/graphshell/web/Cargo.toml', 'ports/graphshell/web/Cargo.lock',
]) sources[path] = digest(await readFile(join(root, path)));
const files = {};
for (const name of await readdir(join(site, 'graphshell'))) {
  const bytes = await readFile(join(site, 'graphshell', name));
  files[name] = { hash: digest(bytes), bytes: bytes.length };
}
await writeFile(join(site, 'graphshell-bindings.json'), JSON.stringify({
  host: 'graphshell-web', feature: 'applets', files, sources,
  component_hash: fixture.component_hash,
  disclosure_revision: disclosure.revision,
}, null, 2));
// The standalone workspace intentionally ignores its lock in Git. Preserve the
// exact lock used for this receipt beside the local proof, so it is reviewable.
await cp(join(root, 'ports/graphshell/web/Cargo.lock'), join(site, '..', 'graphshell-web.Cargo.lock'));
console.log('Graphshell applet fixture built at ' + site);
