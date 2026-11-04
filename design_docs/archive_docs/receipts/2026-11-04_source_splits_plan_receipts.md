# H8 Gemot source-split receipts

Owner: 01a19f86-cb71-7820-a6ac-aaec39d8bfd4. Baseline `3cc7445ea15b1f5ca5bd39441096dfd268ad16bb`.
Compact summaries append under H8's shared 100 MB cap.

## 2026-11-04: untouched selected-source baseline

`cargo test --workspace --locked --no-fail-fast -- --test-threads=1`: exit 0; 242 passed, one ignored, including doctests. All thirteen selected Rust sources remain unchanged. Unrelated relay-pool example work appeared concurrently after selection; it is preserved, excluded from this source pass and grants no new relay/operator qualification.

## 2026-11-04: thirteen originals qualified

| Original | Before | After |
|---|---:|---:|
| `crates/commons/src/call.rs` | 878 | 518 |
| `crates/commons/src/chat.rs` | 3914 | 568 |
| `crates/commons/src/encrypted.rs` | 1031 | 500 |
| `crates/commons/src/lib.rs` | 2138 | 544 |
| `crates/gemot/examples/author-offline-publication.rs` | 1435 | 433 |
| `crates/gemot/src/moot/flora.rs` | 623 | 498 |
| `crates/gemot/src/moot/records/collection.rs` | 699 | 443 |
| `crates/gemot/src/moot/records/roster.rs` | 719 | 359 |
| `crates/gemot/src/moot/records/store.rs` | 1350 | 229 |
| `crates/gemot/src/moot/service.rs` | 2820 | 526 |
| `crates/gemot/src/moot/tulpa.rs` | 755 | 452 |
| `crates/gemot/src/moot/typed_authorization.rs` | 650 | 141 |
| `crates/mien/src/ledger.rs` | 662 | 285 |

All extracted Rust files fit; maximum 568 lines (`crates/commons/src/chat.rs`). Exactly thirteen exceptions retire, leaving zero.

The complete baseline/post native workspace inventories agree: 242 passed,
zero failed, one ignored, including doctests. `cargo test --workspace
--locked --no-fail-fast -- --test-threads=1`, `cargo doc --workspace --locked
--no-deps` and `prek run --all-files` pass. A final warm rerun covers import
cleanup; the actual commit repeats configured ceiling/Clippy checks.
The staged move audit matches 400 bodies, all signatures and type fields,
with no formatting-only differences. Public facade paths remain; test-only
aliases keep their cfg, and child-internal helpers need no unused root alias.

Concurrent relay custody changes were published independently in `30be124`,
which is preserved as an ancestor. All selected sources and Cargo inputs
match the untouched baseline before this pass. No H8 manifest, lockfile,
CI, hook, tool release, CLAUDE or doctrine change. This software pass does
not rerun the author-offline multi-process publication trial or renew any
operator, real-network, physical or other-platform receipt. The existing
`group.rs` unresolved rustdoc link remains outside this selected pass.
Stable approved target, two jobs; no isolated build area/home/worktree.
The aggregate receipt records the immutable source commit after publication.
