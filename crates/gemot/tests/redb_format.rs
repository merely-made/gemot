//! A Moot store in redb 2's file format is refused, not migrated ("No
//! migration, new format only", Mark, 2026-11-13).

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

use gemot::moot::constitution::ConstitutionFileStore;

// redb's header: a 9-byte magic number, the god byte (bit 0 picks the primary
// commit slot), then two 128-byte commit slots from offset 64, each opening
// with its file-format version byte.
const GOD_BYTE: u64 = 9;
const SLOT_0: u64 = 64;
const SLOT_SIZE: u64 = 128;

#[test]
fn a_constitution_store_in_redb_2_format_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("constitution.redb");
    drop(ConstitutionFileStore::open(&path, [1; 32], [2; 32]).unwrap());

    // Mark both commit slots as format v2, the format redb 2 writes by default.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut god = [0u8; 1];
    file.seek(SeekFrom::Start(GOD_BYTE)).unwrap();
    file.read_exact(&mut god).unwrap();
    let mut version = [0u8; 1];
    file.seek(SeekFrom::Start(SLOT_0 + u64::from(god[0] & 1) * SLOT_SIZE))
        .unwrap();
    file.read_exact(&mut version).unwrap();
    assert_eq!(version[0], 3, "a new store is redb file format v3");
    for slot in 0..2 {
        file.seek(SeekFrom::Start(SLOT_0 + slot * SLOT_SIZE))
            .unwrap();
        file.write_all(&[2]).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);

    let Err(err) = ConstitutionFileStore::open(&path, [1; 32], [2; 32]) else {
        panic!("a redb 2 format store opened");
    };
    let message = err.to_string();
    assert!(message.contains("written by redb 2"), "{message}");
    assert!(message.contains("not readable"), "{message}");
}
