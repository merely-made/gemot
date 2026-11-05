// SPDX-License-Identifier: MPL-2.0
//! Governed directory and agreed work on the existing Moot objects lane.
#[cfg(feature = "work-host")]
pub mod keeper;
pub mod namespace;
pub mod discovery;
mod discovery_network;
pub mod work;

use serde::{Deserialize, Serialize};
use servitor::Cap;

pub type RecordId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowEvent {
    Namespace(namespace::NamespaceEvent),
    Work(work::WorkEvent),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowFact {
    pub event: WorkflowEvent,
    pub by: [u8; 32],
    pub op_hash: RecordId,
    /// Complete signed operation survives prefix pruning. A checkpoint signer
    /// cannot manufacture another worker's consent by filling projection fields.
    pub proof: stickleback::DropRecord,
}

impl WorkflowFact {
    pub fn from_operation(op: &p2panda_core::Operation<super::MootExt>) -> Option<Self> {
        if !super::verify(op) {
            return None;
        }
        let (_, super::MootEvent::Workflow { event }) = super::from_operation(op).ok()? else {
            return None;
        };
        Some(Self {
            event,
            by: super::stable_author(op).ok()?,
            op_hash: *op.hash.as_bytes(),
            proof: stickleback::operation_record(op, true),
        })
    }
    pub fn authentic(&self) -> bool {
        let Ok(Some(op)) = stickleback::decode_operation_record::<super::MootExt>(&self.proof)
        else {
            return false;
        };
        if !super::verify(&op)
            || *op.hash.as_bytes() != self.op_hash
            || super::stable_author(&op).ok() != Some(self.by)
        {
            return false;
        }
        let Some(body) = op.body.as_ref() else {
            return false;
        };
        // Decode only a primitive workflow event here. Do not recurse into a
        // checkpoint someone placed inside its purported operation proof.
        let Ok(super::MootEvent::Workflow { event }) =
            p2panda_core::cbor::decode_cbor_strict(body.to_bytes().as_slice())
        else {
            return false;
        };
        event == self.event && event.validate(op.header.extensions.moot_id).is_ok()
    }
    pub fn verified_for(&self, moot: RecordId) -> bool {
        self.authentic()
            && stickleback::decode_operation_record::<super::MootExt>(&self.proof)
                .ok()
                .flatten()
                .is_some_and(|op| op.header.extensions.moot_id == moot)
    }
}

impl WorkflowEvent {
    pub fn validate(&self, moot: [u8; 32]) -> Result<(), String> {
        match self {
            Self::Namespace(event) => event.validate(moot),
            Self::Work(event) => event.validate(moot),
        }
    }
    pub fn cap(&self) -> Cap {
        match self {
            Self::Namespace(event) => namespace::binding_cap(event.binding),
            Self::Work(event) => match event.action {
                work::WorkAction::Offer { .. } => work::offer_cap(event.work),
                _ => work::work_cap(event.work),
            },
        }
    }
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Namespace(event) => event.at_ms,
            Self::Work(event) => event.at_ms,
        }
    }
}

pub(crate) fn hex(id: RecordId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn canonical_ids(ids: &[RecordId], max: usize) -> bool {
    ids.len() <= max && ids.windows(2).all(|pair| pair[0] < pair[1])
}

pub(crate) fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
