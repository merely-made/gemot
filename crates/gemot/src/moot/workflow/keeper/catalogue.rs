// SPDX-License-Identifier: MPL-2.0
//! A derived permitted catalogue. Scroll's broad UDC-inspired digit is a source
//! claim, not full UDC notation, a capability or a confidential discovery topic.
use super::{Job, Keeper, KeeperError, Result};
use crate::moot::workflow::RecordId;
use crate::moot::{ContributionRef, Moot};
use eidetic::retention::CustodyStore;
use eidetic::seal::PayloadSealer;
use eidetic_search::{DocumentHit, DocumentIndex, DocumentIndexConfig, SearchDocument};
use muniment::Backend;
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "gemot/catalogue-document/v1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogueDocument {
    pub version: u16,
    pub address: String,
    pub title: String,
    pub abstract_text: String,
    /// Raw Scroll success suffix 0..9; 4 is Scroll's general/unclassified code.
    pub scroll_subject: Option<u8>,
    pub language: Option<String>,
    pub body: String,
}
impl CatalogueDocument {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let doc: Self = serde_json::from_slice(bytes)?;
        doc.validate()?;
        Ok(doc)
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !super::super::text(&self.address, 2048)
            || !super::super::text(&self.title, 512)
            || self.abstract_text.len() > 8192
            || self.body.len() > 1024 * 1024
            || self.scroll_subject.is_some_and(|v| v > 9)
            || self
                .language
                .as_ref()
                .is_some_and(|s| !super::super::text(s, 64))
        {
            return Err(KeeperError::Refused("invalid catalogue document".into()));
        }
        Ok(())
    }
}
impl Keeper {
    /// Rebuild each request from currently permitted, verified copies. The index
    /// has no authority and is never a serialized cross-audience cache.
    pub async fn search<B: Backend + Clone>(
        &self,
        moot: &Moot<B>,
        store: &mut dyn CustodyStore,
        jobs: &[Job],
        subject: RecordId,
        query: &str,
        scroll_subject: Option<u8>,
        limit: usize,
        at_ms: u64,
        sealer: Option<&dyn PayloadSealer>,
    ) -> Result<Vec<DocumentHit<ContributionRef>>> {
        if query.len() > 4096
            || limit > 100
            || jobs.len() > self.max_jobs
            || scroll_subject.is_some_and(|v| v > 9)
        {
            return Err(KeeperError::Refused(
                "search budget or subject class".into(),
            ));
        }
        let mut docs = std::collections::BTreeMap::new();
        for job in jobs {
            for contribution in job.contributions.keys() {
                let result = self
                    .retrieve(moot, store, job, subject, *contribution, at_ms, sealer)
                    .await;
                let (metadata, bytes) = match result {
                    Ok(value) => value,
                    Err(
                        error @ (KeeperError::Content(_)
                        | KeeperError::Store(_)
                        | KeeperError::Json(_)),
                    ) => return Err(error),
                    Err(_) => continue,
                };
                if metadata.schema
                    != eidetic::SchemaRef::from_id(eidetic::ManifestId::of_blob(SCHEMA.as_bytes()))
                {
                    continue;
                }
                let doc = CatalogueDocument::decode(&bytes)?;
                if scroll_subject.is_some_and(|c| doc.scroll_subject != Some(c)) {
                    continue;
                }
                docs.insert(
                    *contribution,
                    SearchDocument {
                        key: *contribution,
                        primary_address: doc.address,
                        aliases: vec![],
                        title: Some(doc.title),
                        body: Some(format!("{}\n{}", doc.abstract_text, doc.body)),
                    },
                );
            }
        }
        Ok(
            DocumentIndex::from_documents(DocumentIndexConfig::default(), docs.into_values())
                .search(query, limit),
        )
    }
}
