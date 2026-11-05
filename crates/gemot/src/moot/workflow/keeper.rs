// SPDX-License-Identifier: MPL-2.0
//! Host-driven bounded acquisition and restart reconciliation. No transport or timer
//! is selected here. Jobs are claims; Eidetic's checked copy is the custody evidence.
pub mod catalogue;
use super::work::{Agreement, WorkKind};
use super::{RecordId, hex};
use crate::moot::{CollectionVersion, ContributionRef, Moot, MootError};
use eidetic::retention::{self, CustodyStore, Limits};
use eidetic::seal::PayloadSealer;
use eidetic::{BlobManifest, Hash, ManifestId};
use muniment::{Backend, WriteOp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum KeeperError {
    #[error(transparent)]
    Moot(#[from] MootError),
    #[error("keeper: {0}")]
    Refused(String),
    #[error(transparent)]
    Store(#[from] muniment::error::StoreError),
    #[error(transparent)]
    Content(#[from] eidetic::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, KeeperError>;
pub trait WorkFetcher {
    /// The host adapter enforces transport policy and this allocation ceiling.
    fn fetch(
        &mut self,
        manifest: RecordId,
        max_bytes: u64,
    ) -> impl std::future::Future<Output = Result<(BlobManifest, Vec<u8>)>>;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Acquiring,
    Retained,
    Suspended,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub version: u16,
    pub owner: RecordId,
    pub moot: RecordId,
    pub work: RecordId,
    pub agreement: RecordId,
    pub collection: CollectionVersion,
    pub contributions: BTreeMap<ContributionRef, RecordId>,
    pub state: JobState,
}
// CBOR is used for durable jobs because contribution keys are structured values.
fn encode(job: &Job) -> Result<Vec<u8>> {
    p2panda_core::cbor::encode_cbor(job).map_err(|e| KeeperError::Refused(e.to_string()))
}
fn decode(bytes: &[u8]) -> Result<Job> {
    p2panda_core::cbor::decode_cbor_strict(bytes).map_err(|e| KeeperError::Refused(e.to_string()))
}
pub struct Keeper {
    pub owner: RecordId,
    pub policy_revision: RecordId,
    pub limits: Limits,
    pub max_jobs: usize,
    pub max_inputs_per_job: usize,
}
impl Keeper {
    fn prefix(&self) -> String {
        format!("gemot/work-jobs/{}/", hex(self.owner))
    }
    fn key(&self, moot: RecordId, agreement: RecordId) -> String {
        format!("{}{}/{}", self.prefix(), hex(moot), hex(agreement))
    }
    pub async fn jobs(&self, store: &dyn CustodyStore) -> Result<Vec<Job>> {
        let mut keys = store.list(&self.prefix()).await?;
        keys.sort();
        if keys.len() > self.max_jobs {
            return Err(KeeperError::Refused("job ceiling exceeded".into()));
        }
        let mut jobs = Vec::new();
        for key in keys {
            let bytes = store
                .get(&key)
                .await?
                .ok_or_else(|| KeeperError::Refused("missing job".into()))?;
            let job = decode(&bytes)?;
            if job.version != 1
                || job.owner != self.owner
                || key != self.key(job.moot, job.agreement)
                || job.contributions.len() > self.max_inputs_per_job
            {
                return Err(KeeperError::Refused("job identity mismatch".into()));
            }
            jobs.push(job);
        }
        Ok(jobs)
    }
    async fn save(&self, store: &dyn CustodyStore, job: &Job) -> Result<()> {
        let key = self.key(job.moot, job.agreement);
        let prefix = self.prefix();
        let cap = self.max_jobs;
        let bytes = encode(job)?;
        let result = std::sync::Arc::new(std::sync::Mutex::new(Err(
            "job transaction did not run".to_string()
        )));
        let out = result.clone();
        store
            .transact(Box::new(move |reader| {
                let checked = (|| -> std::result::Result<Vec<WriteOp>, String> {
                    if reader.get(&key).map_err(|e| e.to_string())?.is_none()
                        && reader.list(&prefix).map_err(|e| e.to_string())?.len() >= cap
                    {
                        return Err("job ceiling exceeded".into());
                    }
                    Ok(vec![WriteOp::Put { key, value: bytes }])
                })();
                match checked {
                    Ok(writes) => {
                        *out.lock().expect("job transaction") = Ok(());
                        writes
                    }
                    Err(e) => {
                        *out.lock().expect("job transaction") = Err(e);
                        vec![]
                    }
                }
            }))
            .await?;
        result
            .lock()
            .expect("job transaction")
            .clone()
            .map_err(KeeperError::Refused)?;
        Ok(())
    }
    async fn eligible<B: Backend + Clone>(
        &self,
        moot: &Moot<B>,
        work: RecordId,
        at_ms: u64,
    ) -> Result<Agreement> {
        let view = moot.work_view(work, at_ms).await?;
        let agreement = view
            .active_agreement()
            .ok_or_else(|| KeeperError::Refused("no unambiguous active agreement".into()))?;
        let t = &agreement.offer.terms;
        if t.worker != self.owner
            || !matches!(t.kind, WorkKind::Hosting { .. })
            || t.window_at(at_ms).is_none()
            || t.max_bytes > self.limits.max_payload_bytes
        {
            return Err(KeeperError::Refused(
                "wrong worker, window, kind or device ceiling".into(),
            ));
        }
        // Current worker access is mandatory in addition to their old consent.
        moot.collection_for_reader(self.owner, &t.inputs, at_ms)
            .await?;
        Ok(agreement.clone())
    }
    /// Discover an accepted obligation. Save intent, then acquire or repair its
    /// exact current inputs. Retrying reads actual copies, not a remembered flag.
    pub async fn reconcile<B: Backend + Clone, F: WorkFetcher>(
        &self,
        moot: &Moot<B>,
        store: &mut dyn CustodyStore,
        work: RecordId,
        at_ms: u64,
        fetcher: &mut F,
        sealer: Option<&dyn PayloadSealer>,
    ) -> Result<Job> {
        let a = match self.eligible(moot, work, at_ms).await {
            Ok(a) => a,
            Err(error) => {
                for mut job in self
                    .jobs(store)
                    .await?
                    .into_iter()
                    .filter(|j| j.work == work && j.moot == moot.moot_id().0)
                {
                    job.state = JobState::Suspended;
                    self.save(store, &job).await?;
                }
                return Err(error);
            }
        };
        let collection = moot
            .collection_for_reader(self.owner, &a.offer.terms.inputs, at_ms)
            .await?;
        let fauna = moot.authorized_fauna(at_ms).await?;
        let contributions: BTreeMap<_, _> = collection
            .effective_selected
            .iter()
            .map(|r| {
                let f = fauna
                    .iter()
                    .find(|f| f.op_hash == r.share)
                    .expect("effective collection fauna");
                (*r, f.manifest_id)
            })
            .collect();
        if contributions.is_empty() || contributions.len() > self.max_inputs_per_job {
            return Err(KeeperError::Refused(
                "no eligible inputs or input ceiling exceeded".into(),
            ));
        }
        let mut job = Job {
            version: 1,
            owner: self.owner,
            moot: collection.collection.moot_id,
            work,
            agreement: a.id,
            collection: collection.version,
            contributions,
            state: JobState::Acquiring,
        };
        self.save(store, &job).await?;
        let mut total = 0u64;
        let mut seen = std::collections::BTreeSet::new();
        for manifest in job.contributions.values() {
            if !seen.insert(*manifest) {
                continue;
            }
            // Recheck authority before every acquisition and at completion.
            self.eligible(moot, work, at_ms).await?;
            let held = retention::read(store, self.owner, manifest_id(*manifest), sealer).await?;
            let size = if let Some((copy, _, _)) = held {
                copy.payload_bytes
            } else {
                let remaining = a
                    .offer
                    .terms
                    .max_bytes
                    .checked_sub(total)
                    .ok_or_else(|| KeeperError::Refused("agreement byte ceiling".into()))?;
                let (metadata, bytes) = fetcher.fetch(*manifest, remaining).await?;
                if *metadata.id.0.as_bytes() != *manifest || metadata.byte_size > remaining {
                    return Err(KeeperError::Refused(
                        "fetch returned another manifest or exceeded budget".into(),
                    ));
                }
                retention::retain(
                    store,
                    self.owner,
                    &metadata,
                    &bytes,
                    self.limits,
                    self.policy_revision,
                    at_ms,
                    sealer,
                )
                .await?
                .payload_bytes
            };
            total = total
                .checked_add(size)
                .filter(|n| *n <= a.offer.terms.max_bytes)
                .ok_or_else(|| KeeperError::Refused("agreement byte ceiling".into()))?;
        }
        self.eligible(moot, work, at_ms).await?;
        job.state = JobState::Retained;
        self.save(store, &job).await?;
        Ok(job)
    }
    /// Every read checks current worker and reader permissions, exact collection
    /// membership, withdrawal, expiry and the integrity of actual stored bytes.
    pub async fn retrieve<B: Backend + Clone>(
        &self,
        moot: &Moot<B>,
        store: &mut dyn CustodyStore,
        job: &Job,
        subject: RecordId,
        contribution: ContributionRef,
        at_ms: u64,
        sealer: Option<&dyn PayloadSealer>,
    ) -> Result<(BlobManifest, Vec<u8>)> {
        let a = self.eligible(moot, job.work, at_ms).await?;
        let collection = moot
            .collection_for_reader(subject, &a.offer.terms.inputs, at_ms)
            .await?;
        if a.id != job.agreement
            || job.owner != self.owner
            || job.moot != collection.collection.moot_id
            || !collection.effective_selected.contains(&contribution)
        {
            return Err(KeeperError::Refused("inactive or ineligible claim".into()));
        }
        let fauna = moot.authorized_fauna(at_ms).await?;
        let manifest = fauna
            .iter()
            .find(|f| f.op_hash == contribution.share)
            .map(|f| f.manifest_id)
            .ok_or_else(|| KeeperError::Refused("withdrawn contribution".into()))?;
        if job.contributions.get(&contribution) != Some(&manifest) {
            return Err(KeeperError::Refused("claim manifest mismatch".into()));
        }
        let (_, metadata, bytes) =
            retention::read(store, self.owner, manifest_id(manifest), sealer)
                .await?
                .ok_or_else(|| {
                    KeeperError::Refused("copy missing; reconcile acquisition".into())
                })?;
        if metadata.byte_size > a.offer.terms.max_bytes
            || metadata.byte_size > self.limits.max_payload_bytes
        {
            return Err(KeeperError::Refused(
                "retrieval byte ceiling exceeded".into(),
            ));
        }
        Ok((metadata, bytes))
    }
}

fn manifest_id(id: RecordId) -> ManifestId {
    ManifestId(Hash::parse(&format!("blake3:{}", hex(id))).expect("fixed 32-byte BLAKE3 digest"))
}
