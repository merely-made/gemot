// SPDX-License-Identifier: MPL-2.0
//! Synthetic loopback adapter only. Production hosts supply authenticated subjects
//! and their bounded Murm/Eidetic fetch adapter; this test fixes the reader root.
use super::*;
pub fn spawn(dir: &Path, role: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "keeper::process_role",
            "--ignored",
            "--nocapture",
        ])
        .env("GEMOT_WORKFLOW_ROLE", role)
        .env("GEMOT_WORKFLOW_DIR", dir)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}
pub fn run(dir: &Path, role: &str) {
    assert!(spawn(dir, role).wait().unwrap().success(), "{role} child");
}
fn send(stream: &mut TcpStream, metadata: &BlobManifest, bytes: &[u8]) {
    let data = serde_json::to_vec(&(metadata, bytes)).unwrap();
    assert!(data.len() < 200_000);
    stream
        .write_all(&(data.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&data).unwrap();
}
fn receive(stream: &mut TcpStream, max: u64) -> (BlobManifest, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut size = [0; 4];
    stream.read_exact(&mut size).unwrap();
    let size = u32::from_be_bytes(size) as usize;
    assert!(size < 200_000);
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).unwrap();
    let result: (BlobManifest, Vec<u8>) = serde_json::from_slice(&bytes).unwrap();
    assert!(result.1.len() as u64 <= max);
    result
}
struct SocketFetcher {
    address: String,
}
impl WorkFetcher for SocketFetcher {
    async fn fetch(&mut self, id: [u8; 32], max: u64) -> Result<(BlobManifest, Vec<u8>)> {
        let mut socket = TcpStream::connect(&self.address).unwrap();
        socket.write_all(&id).unwrap();
        Ok(receive(&mut socket, max))
    }
}
async fn open(dir: &Path, name: &str) -> MootFile {
    MootFile::open(dir.join(name), ID, root(&person(7)), retention())
        .await
        .unwrap()
}
async fn export(moot: &MootFile, path: &Path) {
    let mut bytes = Vec::new();
    moot.export_plain_drop(
        &mut bytes,
        DropExportProfile::default(),
        DropLimits::default(),
    )
    .await
    .unwrap();
    std::fs::write(path, bytes).unwrap();
}
async fn import(moot: &MootFile, path: &Path) {
    moot.import_plain_drop(
        std::io::Cursor::new(std::fs::read(path).unwrap()),
        DropLimits::default(),
    )
    .await
    .unwrap();
}
pub async fn role(dir: &Path, role: &str) {
    match role {
        "author" => {
            let moot = open(dir, "author").await;
            initialize(&moot).await;
            let bytes = document().encode().unwrap();
            let metadata = manifest(&bytes);
            populate(&moot, *metadata.id.0.as_bytes()).await;
            moot.work_for_identity(
                &person(7),
                event(
                    WorkAction::Offer {
                        terms: terms(),
                        replaces: None,
                    },
                    4,
                ),
            )
            .await
            .unwrap();
            moot.bind_for_identity(&person(7), binding("sites/catalog", vec![]))
                .await
                .unwrap();
            export(&moot, &dir.join("author.drop")).await;
            std::fs::write(
                dir.join("source.json"),
                serde_json::to_vec(&(metadata, bytes)).unwrap(),
            )
            .unwrap();
        }
        "source" => {
            let (metadata, bytes): (BlobManifest, Vec<u8>) =
                serde_json::from_slice(&std::fs::read(dir.join("source.json")).unwrap()).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            std::fs::write(
                dir.join("source.addr"),
                listener.local_addr().unwrap().to_string(),
            )
            .unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut id = [0; 32];
            stream.read_exact(&mut id).unwrap();
            assert_eq!(id, *metadata.id.0.as_bytes());
            send(&mut stream, &metadata, &bytes);
        }
        "acquire" => {
            let moot = open(dir, "keeper-moot").await;
            import(&moot, &dir.join("author.drop")).await;
            let view = moot.work_view(WORK, 5).await.unwrap();
            let offer = *view.offers.keys().next().unwrap();
            moot.work_for_identity(&person(8), event(WorkAction::Accept { offer }, 5))
                .await
                .unwrap();
            let mut store = RedbBackend::open(dir.join("copies.redb")).unwrap();
            let mut source = SocketFetcher {
                address: std::fs::read_to_string(dir.join("source.addr")).unwrap(),
            };
            keeper()
                .reconcile(&moot, &mut store, WORK, 20, &mut source, None)
                .await
                .unwrap();
            export(&moot, &dir.join("agreed.drop")).await;
        }
        "restart" => {
            let moot = open(dir, "keeper-moot").await;
            let mut store = RedbBackend::open(dir.join("copies.redb")).unwrap();
            let k = keeper();
            let mut stopped = Source {
                items: BTreeMap::new(),
                calls: 0,
            };
            let job = k
                .reconcile(&moot, &mut store, WORK, 21, &mut stopped, None)
                .await
                .unwrap();
            assert_eq!(stopped.calls, 0);
            let jobs = k.jobs(&store).await.unwrap();
            let share = *job.contributions.keys().next().unwrap();
            assert_eq!(
                k.search(
                    &moot,
                    &mut store,
                    &jobs,
                    root(&person(9)),
                    "painting",
                    Some(7),
                    10,
                    21,
                    None
                )
                .await
                .unwrap()
                .len(),
                1
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            std::fs::write(
                dir.join("keeper.addr"),
                listener.local_addr().unwrap().to_string(),
            )
            .unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let (metadata, bytes) = k
                .retrieve(&moot, &mut store, &job, root(&person(9)), share, 22, None)
                .await
                .unwrap();
            send(&mut stream, &metadata, &bytes);
            std::fs::write(dir.join("keeper-receipt.json"),serde_json::to_vec_pretty(&serde_json::json!({"scope":"synthetic local processes and loopback","reopened_redb":true,"contributor_running":false,"source_fetches_after_restart":0,"verified_bytes":bytes.len(),"search_subject":7})).unwrap()).unwrap();
        }
        "reader" => {
            let moot = open(dir, "reader-moot").await;
            import(&moot, &dir.join("agreed.drop")).await;
            let collection = moot
                .resolve_name(root(&person(9)), "sites/catalog", 22)
                .await
                .unwrap();
            assert_eq!(collection.effective_selected.len(), 1);
            let mut stream =
                TcpStream::connect(std::fs::read_to_string(dir.join("keeper.addr")).unwrap())
                    .unwrap();
            let (metadata, bytes) = receive(&mut stream, 65536);
            assert_eq!(metadata.content_hash, Hash::of(&bytes));
            assert_eq!(metadata.id.0, Hash::of(&bytes));
            let document = CatalogueDocument::decode(&bytes).unwrap();
            let index = eidetic_search::DocumentIndex::from_documents(
                Default::default(),
                [eidetic_search::SearchDocument {
                    key: collection.effective_selected[0],
                    primary_address: document.address,
                    aliases: vec![],
                    title: Some(document.title),
                    body: Some(format!("{}\n{}", document.abstract_text, document.body)),
                }],
            );
            let hits = index.search("painting", 10);
            assert_eq!(hits.len(), 1);
            // This reviewer has Write capability to report a signed retrieval claim.
            let agreement = moot
                .work_view(WORK, 22)
                .await
                .unwrap()
                .active_agreement()
                .unwrap()
                .id;
            let observed = moot
                .work_for_identity(
                    &person(9),
                    event(
                        WorkAction::Observe {
                            agreement,
                            window: 0,
                            manifest: *metadata.id.0.as_bytes(),
                            bytes: bytes.len() as u64,
                        },
                        22,
                    ),
                )
                .await
                .unwrap();
            let submitted = moot
                .work_for_identity(
                    &person(8),
                    event(
                        WorkAction::Submit {
                            agreement,
                            window: 0,
                            replaces: vec![],
                            outputs: collection.effective_selected,
                            evidence: vec![observed.operation],
                        },
                        23,
                    ),
                )
                .await
                .unwrap();
            moot.work_for_identity(&person(9),event(WorkAction::Review {submission:submitted.operation,replaces:vec![],approve:true,rationale:"Fresh read hash checked; permitted catalogue searched after keeper restart".into()},24)).await.unwrap();
            assert!(
                moot.work_view(WORK, 25).await.unwrap().submissions[&submitted.operation].accepted
            );
            std::fs::write(dir.join("reader-receipt.json"),serde_json::to_vec_pretty(&serde_json::json!({"scope":"synthetic fresh local process","verified_manifest":metadata.id.0.to_hex(),"search_hits":hits.len(),"review_accepted":true,"recognition_awarded":false,"payment_executed":false})).unwrap()).unwrap();
        }
        _ => panic!("unknown process role"),
    }
}
