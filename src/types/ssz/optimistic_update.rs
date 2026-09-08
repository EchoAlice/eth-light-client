use super::{bad_size, RawSyncAggregate};
use crate::chain_spec::Fork;
use crate::error::Result;
use crate::types::consensus::{
    AltairLightClientHeader, BellatrixLightClientHeader, CapellaLightClientHeader,
    DenebLightClientHeader, ElectraLightClientHeader, LightClientOptimisticUpdate,
};
use ssz_derive::Decode;
use ssz_types::typenum::Unsigned;

impl LightClientOptimisticUpdate {
    pub fn from_ssz(
        _bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
    ) -> Result<LightClientOptimisticUpdate> {
        match fork {
            Fork::Altair => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                n => Err(bad_size(n)),
            },
            Fork::Bellatrix => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                n => Err(bad_size(n)),
            },
            Fork::Capella => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                n => Err(bad_size(n)),
            },
            Fork::Deneb => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                n => Err(bad_size(n)),
            },
            Fork::Electra => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                n => Err(bad_size(n)),
            },
        }
    }
}

#[derive(Decode)]
struct _RawAltairOptimisticUpdate<N: Unsigned> {
    attested_header: AltairLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

#[derive(Decode)]
struct _RawBellatrixOptimisticUpdate<N: Unsigned> {
    attested_header: BellatrixLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

#[derive(Decode)]
struct _RawCapellaOptimisticUpdate<N: Unsigned> {
    attested_header: CapellaLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

#[derive(Decode)]
struct _RawDenebOptimisticUpdate<N: Unsigned> {
    attested_header: DenebLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

#[derive(Decode)]
struct _RawElectraOptimisticUpdate<N: Unsigned> {
    attested_header: ElectraLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}
