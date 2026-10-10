// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

// jco is a development dependency for this proof, not a platform dependency.
import { readFile, writeFile, mkdir, cp, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, join, dirname } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { blake3 } from '@noble/hashes/blake3.js';

const here = dirname(fileURLToPath(import.meta.url));
const runtime = resolve(here, '../../../../../ports/graphshell/web/applets');
if (!process.argv[2]) throw new Error('Pass the proof run’s site directory');
const site = resolve(process.argv[2]);
const fixture = JSON.parse(await readFile(join(site, 'fixture.json'), 'utf8'));
const component = await readFile(join(site, 'library.wasm'));
const digest = bytes => Buffer.from(blake3(bytes)).toString('hex');
const part = fixture.app.manifest.parts[0];
if (digest(component) !== fixture.component_hash || part.blob !== `blake3:${digest(component)}` || part.bytes !== component.length) {
  throw new Error('Build refuses substituted component bytes');
}
const jco = JSON.parse(await readFile(join(here, 'node_modules/@bytecodealliance/jco/package.json'), 'utf8'));
await mkdir(join(site, 'generated'), { recursive: true });
const command = typeof jco.bin === 'string' ? jco.bin : jco.bin.jco;
await promisify(execFile)(process.execPath, [join(here, 'node_modules/@bytecodealliance/jco', command),
  'transpile', join(site, 'library.wasm'), '--name', 'library', '--instantiation', 'async',
  '--no-wasi-shim', '--no-nodejs-compat', '-o', join(site, 'generated')]);
const files = {};
for (const name of await readdir(join(site, 'generated'))) {
  if (name.endsWith('.js') || name.endsWith('.wasm')) {
    const bytes = await readFile(join(site, 'generated', name));
    files[name] = { hash: digest(bytes), bytes: bytes.length };
  }
}
const host_sources = {};
await cp(join(here, 'node_modules/@noble/hashes'), join(site, 'noble'), { recursive: true, dereference: true });
for (const name of ['index.html', 'browser.mjs', 'worker.mjs', 'verify.mjs', 'wasi.mjs', 'runtime.mjs']) {
  const source = ['worker.mjs', 'verify.mjs', 'wasi.mjs', 'runtime.mjs'].includes(name) ? runtime : here;
  await cp(join(source, name), join(site, name));
  host_sources[name] = digest(await readFile(join(source, name)));
}
const bindings = JSON.stringify({ jco: jco.version, component_hash: digest(component), files, host_sources }, null, 2);
await writeFile(join(site, 'bindings.json'), bindings);
fixture.browser_bindings_hash = digest(new TextEncoder().encode(bindings));
await writeFile(join(site, 'fixture.json'), JSON.stringify(fixture, null, 2));
console.log(`Browser host built at ${site}; component blake3:${digest(component)}`);
