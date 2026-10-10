// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

import init, * as gs from './graphshell/graphshell_web.js';
import { mountCapsuleApplet } from './host.mjs';
window.graphshellErrors = [];
window.addEventListener('error', event => window.graphshellErrors.push(String(event.message)));
window.addEventListener('unhandledrejection', event => window.graphshellErrors.push(String(event.reason)));
try {
  await init();
  window.graphshellWasm = gs;
  const root = document.querySelector('graphshell-tree');
  gs.mount_tree(root);
  const deadline = performance.now() + 60000;
  while (root.dataset.ready !== 'true') {
    if (performance.now() > deadline) throw new Error('Graphshell tree mount timed out');
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  window.graphshellConfig = await (await fetch('./graphshell-config.json')).json();
  window.graphshellApplet = await mountCapsuleApplet(root, gs, window.graphshellConfig);
  document.title = 'Graphshell · Moot capsule library';
  root.dataset.appletReady = 'true';
} catch (error) {
  window.graphshellErrors.push(String(error));
  document.getElementById('boot-error').textContent = String(error);
}
