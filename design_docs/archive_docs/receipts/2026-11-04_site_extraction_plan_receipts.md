# Shared site extraction receipts

## 2026-11-04: native receiving source

Donors: Mere `a9fa5c85c` in the reused extraction worktree and Knot
`7e66a1dfd644e74fea775d5782a4436ebc09ff95`. Full donor revisions, tracked blobs,
raw hashes and package input identities are under
`Code/testing/subsystem-extractions-20261104`; the two crates also keep
`source-import.json`. Ten model and twenty-seven host Rust files compare with
only package import/binary-lookup renames. All eight native V1 fixture files
are unchanged. History salts, intent strings and runtime function bodies retain
their original behavior. Two existing source-size exceptions follow their files.

Original and receiving suites: **31 model tests** and **44 host tests**, with
five separate ignored process/helper cases. Both default library MSRV checks
pass on Rust 1.97.1. Unused donor patches were removed with identical full
resolved package identities and features. Older Cargo normalized the model
lockfile without changing any package identity. Default normal/build graphs
contain 47 model and 102 host packages and exclude the community runtime,
editor and renderer; all-feature graphs also contain no Mere or Genet source.

Detailed commands, outcomes, warnings and intermediate failed setup checks stay
in `gates.jsonl` and its logs. The initial missing donor-relative patch and
lockfile-normalization failures are not acceptance receipts. New Markdown/HTML
writers, scripting, the general agreed-work workflow, physical peers and headed
acceptance are outside this receiving source gate.
