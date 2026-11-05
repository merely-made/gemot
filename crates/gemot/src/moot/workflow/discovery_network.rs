// SPDX-License-Identifier: MPL-2.0
//! Publish the bounded authority/collection prelude before an ephemeral hint.
use crate::moot::{Moot, MootLanes};
use muniment::Backend;
use p2panda_store::topics::TopicStore;
impl MootLanes {
    pub async fn publish_catalogue_history<B: Backend + Clone>(
        &self,
        moot: &Moot<B>,
        max_operations: usize,
    ) -> Result<(), String> {
        let store = moot.constitution_store();
        let logs: std::collections::BTreeMap<p2panda_core::VerifyingKey, Vec<u64>> = store
            .resolve(&p2panda_core::Topic::from(moot.moot_id().0))
            .await
            .map_err(|e| e.to_string())?;
        let mut law = Vec::new();
        for (author, ids) in logs {
            for id in ids {
                if let Some(entries) = store
                    .get_log_entries(&author, &id, None, None)
                    .await
                    .map_err(|e| e.to_string())?
                {
                    law.extend(entries.into_iter().map(|(op, _)| op));
                }
            }
        }
        let objects = moot
            .object_store()
            .ops(moot.moot_id().0)
            .await
            .map_err(|e| e.to_string())?;
        if law.len().saturating_add(objects.len()) > max_operations {
            return Err("catalogue history publication budget exceeded".into());
        }
        for op in law {
            self.constitution.publish(op).map_err(|e| e.to_string())?;
        }
        for op in objects {
            self.records.publish(op).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
