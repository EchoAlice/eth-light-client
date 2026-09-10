use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U32, U512, U6, U7};
use ssz_types::FixedVector;

use super::{assemble_finality_proof, bad_size, decode_as, RawSyncAggregate};
use crate::chain_spec::Fork;
use crate::error::Result;
use crate::types::consensus::LightClientHeader::{Altair, Bellatrix, Capella, Deneb, Electra};
use crate::types::consensus::{
    AltairLightClientHeader, BellatrixLightClientHeader, CapellaLightClientHeader,
    DenebLightClientHeader, ElectraLightClientHeader, LightClientFinalityUpdate,
};
use crate::types::primitives::Root;

impl LightClientFinalityUpdate {
    pub fn from_ssz(
        bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
    ) -> Result<LightClientFinalityUpdate> {
        match fork {
            Fork::Altair => match sync_committee_size {
                32 => decode_as::<RawAltairFinalityUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawAltairFinalityUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Bellatrix => match sync_committee_size {
                32 => decode_as::<RawBellatrixFinalityUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawBellatrixFinalityUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Capella => match sync_committee_size {
                32 => decode_as::<RawCapellaFinalityUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawCapellaFinalityUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Deneb => match sync_committee_size {
                32 => decode_as::<RawDenebFinalityUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawDenebFinalityUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Electra => match sync_committee_size {
                32 => decode_as::<RawElectraFinalityUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawElectraFinalityUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
        }
    }
}

#[derive(Decode)]
struct RawAltairFinalityUpdate<N: Unsigned> {
    attested_header: AltairLightClientHeader,
    finalized_header: AltairLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawAltairFinalityUpdate<N> {
    fn into_update(self) -> Result<LightClientFinalityUpdate> {
        let finalized =
            assemble_finality_proof(Altair(self.finalized_header), self.finality_branch.to_vec())?;

        Ok(LightClientFinalityUpdate {
            attested_header: Altair(self.attested_header),
            finalized,
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        })
    }
}

#[derive(Decode)]
struct RawBellatrixFinalityUpdate<N: Unsigned> {
    attested_header: BellatrixLightClientHeader,
    finalized_header: BellatrixLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawBellatrixFinalityUpdate<N> {
    fn into_update(self) -> Result<LightClientFinalityUpdate> {
        let finalized = assemble_finality_proof(
            Bellatrix(self.finalized_header),
            self.finality_branch.to_vec(),
        )?;

        Ok(LightClientFinalityUpdate {
            attested_header: Bellatrix(self.attested_header),
            finalized,
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        })
    }
}

#[derive(Decode)]
struct RawCapellaFinalityUpdate<N: Unsigned> {
    attested_header: CapellaLightClientHeader,
    finalized_header: CapellaLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawCapellaFinalityUpdate<N> {
    fn into_update(self) -> Result<LightClientFinalityUpdate> {
        let finalized = assemble_finality_proof(
            Capella(self.finalized_header),
            self.finality_branch.to_vec(),
        )?;

        Ok(LightClientFinalityUpdate {
            attested_header: Capella(self.attested_header),
            finalized,
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        })
    }
}

#[derive(Decode)]
struct RawDenebFinalityUpdate<N: Unsigned> {
    attested_header: DenebLightClientHeader,
    finalized_header: DenebLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawDenebFinalityUpdate<N> {
    fn into_update(self) -> Result<LightClientFinalityUpdate> {
        let finalized =
            assemble_finality_proof(Deneb(self.finalized_header), self.finality_branch.to_vec())?;

        Ok(LightClientFinalityUpdate {
            attested_header: Deneb(self.attested_header),
            finalized,
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        })
    }
}

#[derive(Decode)]
struct RawElectraFinalityUpdate<N: Unsigned> {
    attested_header: ElectraLightClientHeader,
    finalized_header: ElectraLightClientHeader,
    finality_branch: FixedVector<Root, U7>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawElectraFinalityUpdate<N> {
    fn into_update(self) -> Result<LightClientFinalityUpdate> {
        let finalized = assemble_finality_proof(
            Electra(self.finalized_header),
            self.finality_branch.to_vec(),
        )?;

        Ok(LightClientFinalityUpdate {
            attested_header: Electra(self.attested_header),
            finalized,
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        })
    }
}
