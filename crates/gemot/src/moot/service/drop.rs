// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<B: Backend + Clone> Moot<B> {
    /// Recover an authored operation for host-side publication. This is the
    /// only operation-typed aggregate API: transport ownership stays outside
    /// Gemot while commands and receipts stay plain.
    pub async fn outbound(
        &self,
        receipt: &MootCommandReceipt,
    ) -> Result<MootOutboundOperation, MootError> {
        let hash = p2panda_core::Hash::from_bytes(receipt.operation);
        match receipt.lane {
            MootLane::Membership => self
                .membership
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Membership)
                .ok_or(MootError::OutboundMissing),
            MootLane::Objects => self
                .objects
                .operation(&hash)
                .await?
                .map(MootOutboundOperation::Object)
                .ok_or(MootError::OutboundMissing),
            MootLane::Standing => self
                .standing
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Standing)
                .ok_or(MootError::OutboundMissing),
            MootLane::Tulpa => self
                .tulpa
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Tulpa)
                .ok_or(MootError::OutboundMissing),
            MootLane::Flora => self
                .flora
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Flora)
                .ok_or(MootError::OutboundMissing),
        }
    }

    /// Author the next checkpoint under the currently accepted constitution.
    pub async fn checkpoint(
        &self,
        actor_seed: [u8; 32],
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.refresh_retention_authority().await?;
        let checkpoint = self.objects.build_checkpoint(self.moot_id.0, at_ms).await?;
        self.author_object(
            actor_seed,
            MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(checkpoint),
            },
        )
        .await
    }

    /// Retire this actor's event prefix at the latest accepted checkpoint.
    pub async fn prune_current(
        &self,
        actor_seed: [u8; 32],
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        let checkpoint = self
            .objects
            .latest_checkpoint(self.moot_id.0)
            .await?
            .ok_or(MootError::CheckpointMissing)?;
        let operation = self
            .objects
            .author_prune_seed(actor_seed, self.moot_id.0, checkpoint.operation, at_ms)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }

    pub(super) async fn aggregate_drop_records(
        &self,
        selector: &MootDropSelector,
        budget: DropExportBudget,
    ) -> Result<Vec<DropRecord>, MootError> {
        let evidence = ConstitutionEvidence {
            version: CONSTITUTION_EVIDENCE_VERSION,
            operations: self.governance.drop_records().await?,
        };
        let evidence_bytes =
            encode_cbor(&evidence).map_err(|_| MootError::ConstitutionEvidenceMalformed)?;
        let mut records = vec![DropRecord::Evidence {
            kind: EvidenceKind::CheckpointAuthorization,
            subject: self.moot_id.0,
            bytes: evidence_bytes,
            critical: true,
        }];
        let delegation = DelegationEvidence {
            version: DELEGATION_EVIDENCE_VERSION,
            operations: self.delegations.drop_records().await?,
        };
        let delegation_bytes =
            encode_cbor(&delegation).map_err(|_| MootError::DelegationEvidenceMalformed)?;
        records.push(DropRecord::Evidence {
            kind: EvidenceKind::CapabilityChain,
            subject: self.moot_id.0,
            bytes: delegation_bytes,
            critical: true,
        });
        let domains = DomainEvidence {
            version: DOMAIN_EVIDENCE_VERSION,
            membership_operations: self.membership.drop_records().await?,
            standing_operations: export_topic_operations::<B, StandingExt, u64>(
                &self.standing.sync_store(),
                &p2panda_core::Topic::from(self.moot_id.0),
                DropExportProfile::default(),
            )
            .await
            .map_err(|_| MootError::DomainEvidenceMalformed)?,
            tulpa_operations: export_topic_operations::<B, TulpaExt, u64>(
                &self.tulpa.sync_store(),
                &p2panda_core::Topic::from(self.moot_id.0),
                DropExportProfile::default(),
            )
            .await
            .map_err(|_| MootError::DomainEvidenceMalformed)?,
            flora_operations: export_topic_operations::<B, FloraExt, u64>(
                &self.flora.sync_store(),
                &p2panda_core::Topic::from(self.moot_id.0),
                DropExportProfile::default(),
            )
            .await
            .map_err(|_| MootError::DomainEvidenceMalformed)?,
        };
        let domain_bytes = encode_cbor(&domains).map_err(|_| MootError::DomainEvidenceMalformed)?;
        records.push(DropRecord::Evidence {
            kind: EvidenceKind::DomainOperations,
            subject: self.moot_id.0,
            bytes: domain_bytes,
            critical: true,
        });
        let (objects, selection) = self
            .objects
            .export_selected_drop_records(self.moot_id.0, selector, budget)
            .await?;
        if selection.budget_omitted != 0 || selection.policy_omitted != 0 {
            return Err(MootError::IncompleteDropBudget(
                selection.budget_omitted + selection.policy_omitted,
            ));
        }
        records.extend(objects);
        Ok(records)
    }

    /// Extract at most one critical evidence section of `kind` addressed to
    /// this Moot.
    ///
    /// Every section obeys the same three rules -- one occurrence, our subject,
    /// and a body that round-trips to exactly the bytes it arrived as, so an
    /// importer cannot be handed a re-encoding that means something else. The
    /// three callers differ only in the wire type, its version and the error
    /// they report, so the rules live here once rather than in three copies
    /// that could drift apart.
    pub(super) fn evidence_section<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        records: &[DropRecord],
        kind: EvidenceKind,
        version: u16,
        version_of: impl Fn(&T) -> u16,
        malformed: impl Fn() -> MootError,
    ) -> Result<Option<T>, MootError> {
        let mut found = None;
        for record in records {
            let DropRecord::Evidence {
                kind: record_kind,
                subject,
                bytes,
                critical: true,
            } = record
            else {
                continue;
            };
            if *record_kind != kind {
                continue;
            }
            if *subject != self.moot_id.0 || found.is_some() {
                return Err(malformed());
            }
            let evidence: T = decode_cbor_strict(&bytes[..]).map_err(|_| malformed())?;
            if version_of(&evidence) != version
                || encode_cbor(&evidence).ok().as_deref() != Some(bytes.as_slice())
            {
                return Err(malformed());
            }
            found = Some(evidence);
        }
        Ok(found)
    }

    pub(super) fn constitution_evidence(
        &self,
        records: &[DropRecord],
    ) -> Result<Vec<DropRecord>, MootError> {
        self.evidence_section::<ConstitutionEvidence>(
            records,
            EvidenceKind::CheckpointAuthorization,
            CONSTITUTION_EVIDENCE_VERSION,
            |evidence| evidence.version,
            || MootError::ConstitutionEvidenceMalformed,
        )?
        .map(|evidence| evidence.operations)
        .ok_or(MootError::ConstitutionEvidenceMissing)
    }

    pub(super) fn delegation_evidence(
        &self,
        records: &[DropRecord],
    ) -> Result<Vec<DropRecord>, MootError> {
        Ok(self
            .evidence_section::<DelegationEvidence>(
                records,
                EvidenceKind::CapabilityChain,
                DELEGATION_EVIDENCE_VERSION,
                |evidence| evidence.version,
                || MootError::DelegationEvidenceMalformed,
            )?
            .map(|evidence| evidence.operations)
            .unwrap_or_default())
    }

    pub(super) fn domain_evidence(
        &self,
        records: &[DropRecord],
    ) -> Result<DomainEvidence, MootError> {
        Ok(self
            .evidence_section::<DomainEvidence>(
                records,
                EvidenceKind::DomainOperations,
                DOMAIN_EVIDENCE_VERSION,
                |evidence| evidence.version,
                || MootError::DomainEvidenceMalformed,
            )?
            .unwrap_or(DomainEvidence {
                version: DOMAIN_EVIDENCE_VERSION,
                membership_operations: Vec::new(),
                standing_operations: Vec::new(),
                tulpa_operations: Vec::new(),
                flora_operations: Vec::new(),
            }))
    }

    pub(super) async fn accept_standing_drop_records(
        &self,
        records: &[DropRecord],
    ) -> Result<u64, MootError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<StandingExt>(record)
                .map_err(|_| MootError::DomainEvidenceMalformed)?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootError::DomainEvidenceMalformed);
            }
            accepted += u64::from(self.standing.accept(self.moot_id.0, &operation).await?);
        }
        Ok(accepted)
    }

    pub(super) async fn accept_tulpa_drop_records(
        &self,
        records: &[DropRecord],
    ) -> Result<u64, MootError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<TulpaExt>(record)
                .map_err(|_| MootError::DomainEvidenceMalformed)?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootError::DomainEvidenceMalformed);
            }
            accepted += u64::from(self.tulpa.accept(self.moot_id.0, &operation).await?);
        }
        Ok(accepted)
    }

    pub(super) async fn accept_flora_drop_records(
        &self,
        records: &[DropRecord],
    ) -> Result<u64, MootError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<FloraExt>(record)
                .map_err(|_| MootError::DomainEvidenceMalformed)?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootError::DomainEvidenceMalformed);
            }
            accepted += u64::from(self.flora.accept(self.moot_id.0, &operation).await?);
        }
        Ok(accepted)
    }

    pub(super) async fn import_aggregate_records(
        &self,
        drop_id: DropId,
        records: Vec<DropRecord>,
    ) -> Result<MootDropImportReceipt, MootError> {
        let evidence = self.constitution_evidence(&records)?;
        let constitution_operations = self.governance.accept_drop_records(&evidence).await?;
        let delegation_evidence = self.delegation_evidence(&records)?;
        let delegation_operations = self
            .delegations
            .accept_drop_records(&delegation_evidence)
            .await?;
        let domains = self.domain_evidence(&records)?;
        let membership_operations = self
            .membership
            .accept_drop_records(&domains.membership_operations)
            .await?;
        let standing_operations = self
            .accept_standing_drop_records(&domains.standing_operations)
            .await?;
        let tulpa_operations = self
            .accept_tulpa_drop_records(&domains.tulpa_operations)
            .await?;
        let flora_operations = self
            .accept_flora_drop_records(&domains.flora_operations)
            .await?;
        // The evidence becomes active before the object lane examines its
        // checkpoint chain. This is the dependency order a fresh device needs
        // after a signer rotation.
        self.refresh_retention_authority().await?;
        let import = self
            .objects
            .import_drop_records(self.moot_id.0, drop_id, records)
            .await?;
        Ok(MootDropImportReceipt {
            import,
            constitution_operations,
            delegation_operations,
            membership_operations,
            standing_operations,
            tulpa_operations,
            flora_operations,
            snapshot: self.snapshot().await?,
        })
    }

    /// Export public or explicitly local Moot state as a self-contained native
    /// drop. The carrier includes critical constitution authority evidence.
    pub async fn export_plain_drop<W: Write>(
        &self,
        writer: &mut W,
        profile: DropExportProfile,
        limits: DropLimits,
    ) -> Result<DropWriteReceipt, MootError> {
        if !profile.include_operation_bodies {
            return Err(MootError::HeaderOnlyDrop);
        }
        let records = self
            .aggregate_drop_records(&MootDropSelector::default(), DropExportBudget::default())
            .await?;
        Ok(write_plain_drop(writer, &records, limits)?)
    }

    /// Export a protected, importable Moot drop. A caller supplies its group
    /// protection suite; Gemot never picks keys or silently falls back to
    /// plaintext.
    pub async fn export_protected_drop<W: Write, D: DropProtector>(
        &self,
        writer: &mut W,
        selector: &MootDropSelector,
        budget: DropExportBudget,
        limits: DropLimits,
        protector: &D,
    ) -> Result<DropWriteReceipt, MootError> {
        let records = self.aggregate_drop_records(selector, budget).await?;
        Ok(write_protected_drop(writer, &records, limits, protector)?)
    }

    /// Import a self-contained plaintext/public Moot drop. Critical
    /// constitution evidence is admitted before the checkpoint chain.
    pub async fn import_plain_drop<R: Read>(
        &self,
        reader: R,
        limits: DropLimits,
    ) -> Result<MootDropImportReceipt, MootError> {
        let (read, records) = read_plain_drop(reader, limits)?;
        self.import_aggregate_records(read.id, records).await
    }

    /// Import a protected Moot drop through the caller's group-key suite.
    pub async fn import_protected_drop<R: Read, D: DropProtector>(
        &self,
        reader: R,
        limits: DropLimits,
        protector: &D,
    ) -> Result<MootDropImportReceipt, MootError> {
        let (read, records) = read_protected_drop(reader, limits, protector)?;
        self.import_aggregate_records(read.id, records).await
    }
}
