// TODO(#146): scaffolding for the finality decoder — grid arms, conversions,
// and remaining raws land in the follow-up slice; drop this allow then.
#![allow(dead_code)]

use super::RawSyncAggregate;
use crate::chain_spec::Fork;
use crate::types::consensus::{AltairLightClientHeader, LightClientFinalityUpdate};
use crate::types::primitives::Root;
use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U6};
use ssz_types::FixedVector;

impl LightClientFinalityUpdate {
    fn _from_ssz(
        _bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
    ) -> LightClientFinalityUpdate {
        match fork {
            Fork::Altair => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                _n => todo!(),
            },
            Fork::Bellatrix => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                _n => todo!(),
            },
            Fork::Capella => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                _n => todo!(),
            },
            Fork::Deneb => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                _n => todo!(),
            },
            Fork::Electra => match sync_committee_size {
                32 => todo!(),
                512 => todo!(),
                _n => todo!(),
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
    fn into_update() -> LightClientFinalityUpdate {
        todo!()
    }
}
