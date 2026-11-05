// SPDX-License-Identifier: MPL-2.0
//! Names refer to stable resources. Concurrent heads and duplicate names fail closed.
use super::{RecordId, WorkflowEvent, canonical_ids, hex, text};
use crate::moot::{CollectionEvent, CollectionRef, CollectionVersion, CollectionView, MootRoster};
use serde::{Deserialize, Serialize};
use servitor::{AuthorityProvider, Cap, Mode, Subject};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionTarget {
    Pinned(CollectionVersion),
    FollowAccepted(CollectionRef),
}
impl CollectionTarget {
    pub fn collection(&self) -> CollectionRef {
        match self {
            Self::Pinned(v) => v.collection,
            Self::FollowAccepted(r) => *r,
        }
    }
    pub fn validate(&self, moot: RecordId) -> bool {
        self.collection().moot_id == moot
            && match self {
                Self::Pinned(v) => !v.frontier.is_empty() && canonical_ids(&v.frontier, 64),
                Self::FollowAccepted(_) => true,
            }
    }
    pub fn resolve(
        &self,
        roster: &MootRoster,
        authority: &impl AuthorityProvider,
    ) -> Option<CollectionView> {
        let collection = self.collection();
        let mut at_version = roster.clone();
        if let Self::Pinned(version) = self {
            let mut included: BTreeSet<_> = version.frontier.iter().copied().collect();
            loop {
                let before = included.len();
                for fact in &roster.collections {
                    if included.contains(&fact.op_hash) {
                        if let CollectionEvent::Changed { parents, .. } = &fact.event {
                            included.extend(parents);
                        }
                    }
                }
                if before == included.len() {
                    break;
                }
            }
            at_version
                .collections
                .retain(|f| included.contains(&f.op_hash));
        }
        let view = at_version.authorized_collection(
            collection.moot_id,
            collection.collection_id,
            authority,
        )?;
        if matches!(self, Self::Pinned(v) if v != &view.version) {
            return None;
        }
        Some(view)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceBinding {
    pub name: String,
    pub target: CollectionTarget,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceEvent {
    pub version: u16,
    pub binding: RecordId,
    pub parents: Vec<RecordId>,
    /// None is a removal. A rename retains the binding id and capability.
    pub value: Option<NamespaceBinding>,
    pub at_ms: u64,
}
impl NamespaceEvent {
    pub fn validate(&self, moot: RecordId) -> Result<(), String> {
        let valid = self.version == 1
            && canonical_ids(&self.parents, 64)
            && self
                .value
                .as_ref()
                .is_none_or(|v| valid_name(&v.name) && v.target.validate(moot));
        if valid {
            Ok(())
        } else {
            Err("invalid namespace grammar or foreign target".into())
        }
    }
}
pub fn valid_name(name: &str) -> bool {
    text(name, 256)
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.trim() == part
                && !part.contains('\\')
        })
}
pub fn binding_cap(binding: RecordId) -> Cap {
    Cap::scope(&format!("moot/namespace/{}", hex(binding))).expect("fixed scope")
}
/// Read is a different scope from collection mutation, independent of its display name.
pub fn collection_read_cap(collection: CollectionRef) -> Cap {
    Cap::scope(&format!(
        "moot/read/collection/{}",
        hex(collection.collection_id.0)
    ))
    .expect("fixed scope")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingView {
    pub binding: RecordId,
    pub heads: Vec<RecordId>,
    pub value: Option<NamespaceBinding>,
    pub conflict: bool,
    pub pending: Vec<RecordId>,
}
impl MootRoster {
    pub fn namespace(&self, binding: RecordId, authority: &impl AuthorityProvider) -> BindingView {
        let mut candidates: BTreeMap<_, _> = self
            .workflow
            .iter()
            .filter(|f| f.authentic())
            .filter_map(|f| match &f.event {
                WorkflowEvent::Namespace(e)
                    if e.binding == binding
                        && authority.covers(
                            Subject::new(f.by),
                            &binding_cap(binding),
                            Mode::Write,
                        ) =>
                {
                    Some((f.op_hash, e))
                }
                _ => None,
            })
            .collect();
        let mut accepted = BTreeMap::new();
        loop {
            let ready: Vec<_> = candidates
                .iter()
                .filter(|(_, e)| e.parents.iter().all(|p| accepted.contains_key(p)))
                .map(|(id, _)| *id)
                .collect();
            if ready.is_empty() {
                break;
            }
            for id in ready {
                accepted.insert(id, candidates.remove(&id).expect("candidate"));
            }
        }
        let parented: BTreeSet<_> = accepted
            .values()
            .flat_map(|e| e.parents.iter().copied())
            .collect();
        let heads: Vec<_> = accepted
            .keys()
            .filter(|id| !parented.contains(*id))
            .copied()
            .collect();
        let value = heads.first().and_then(|h| accepted[h].value.clone());
        let conflict = heads.iter().any(|h| accepted[h].value != value);
        BindingView {
            binding,
            heads,
            value: if conflict { None } else { value },
            conflict,
            pending: candidates.into_keys().collect(),
        }
    }
    pub fn directory(&self, authority: &impl AuthorityProvider) -> Vec<BindingView> {
        let ids: BTreeSet<_> = self
            .workflow
            .iter()
            .filter_map(|f| match &f.event {
                WorkflowEvent::Namespace(e) => Some(e.binding),
                _ => None,
            })
            .collect();
        let mut views: Vec<_> = ids
            .into_iter()
            .map(|id| self.namespace(id, authority))
            .collect();
        let mut names: BTreeMap<String, usize> = BTreeMap::new();
        for view in &views {
            if let Some(v) = &view.value {
                *names.entry(v.name.clone()).or_default() += 1;
            }
        }
        for view in &mut views {
            if view.value.as_ref().is_some_and(|v| names[&v.name] > 1) {
                view.conflict = true;
                view.value = None;
            }
        }
        views
    }
}
