use gemot_site_host::{Publication, PublishedSnapshotV1, Site, SiteFormat};

#[test]
fn saved_publication_round_trips_through_a_canonical_process_neutral_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create_for(&temp.path().join("site"), SiteFormat::Gemini).unwrap();
    let publication = site.publication().unwrap();
    let encoded = publication.to_snapshot_v1().unwrap().encode().unwrap();
    let snapshot: site_model::PublishedSnapshotV1 = PublishedSnapshotV1::decode(&encoded).unwrap();
    assert_eq!(snapshot.encode().unwrap(), encoded);
    let restored = Publication::from_snapshot_v1(snapshot).unwrap();
    let url = url::Url::parse("gemini://localhost:1965/").unwrap();
    assert_eq!(restored.gemini_reply(&url, 1965).code, 20);
}

#[test]
fn snapshot_rejects_noncanonical_or_incomplete_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create_for(&temp.path().join("site"), SiteFormat::Gemini).unwrap();
    let mut bytes = site
        .publication()
        .unwrap()
        .to_snapshot_v1()
        .unwrap()
        .encode()
        .unwrap();
    bytes.extend_from_slice(b"\n");
    assert!(PublishedSnapshotV1::decode(&bytes).is_err());
}

#[test]
fn snapshot_rejects_case_insensitive_duplicate_page_names() {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create_for(&temp.path().join("site"), SiteFormat::Gemini).unwrap();
    let mut snapshot = site.publication().unwrap().to_snapshot_v1().unwrap();
    let mut duplicate = snapshot.pages.remove("/about.gmi").unwrap();
    duplicate.metadata.path = "INDEX.gmi".into();
    snapshot.pages.insert("/INDEX.gmi".into(), duplicate);
    assert!(snapshot.validate().is_err());
}
