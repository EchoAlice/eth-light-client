use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U32, U512};

use super::{bad_size, decode_as, RawSyncAggregate};
use crate::chain_spec::Fork;
use crate::error::Result;
use crate::types::consensus::LightClientHeader::{Altair, Bellatrix, Capella, Deneb, Electra};
use crate::types::consensus::{
    AltairLightClientHeader, BellatrixLightClientHeader, CapellaLightClientHeader,
    DenebLightClientHeader, ElectraLightClientHeader, LightClientOptimisticUpdate,
};

impl LightClientOptimisticUpdate {
    pub fn from_ssz(
        bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
    ) -> Result<LightClientOptimisticUpdate> {
        match fork {
            Fork::Altair => match sync_committee_size {
                32 => Ok(decode_as::<RawAltairOptimisticUpdate<U32>>(bytes)?.into_update()),
                512 => Ok(decode_as::<RawAltairOptimisticUpdate<U512>>(bytes)?.into_update()),
                n => Err(bad_size(n)),
            },
            Fork::Bellatrix => match sync_committee_size {
                32 => Ok(decode_as::<RawBellatrixOptimisticUpdate<U32>>(bytes)?.into_update()),
                512 => Ok(decode_as::<RawBellatrixOptimisticUpdate<U512>>(bytes)?.into_update()),
                n => Err(bad_size(n)),
            },
            Fork::Capella => match sync_committee_size {
                32 => Ok(decode_as::<RawCapellaOptimisticUpdate<U32>>(bytes)?.into_update()),
                512 => Ok(decode_as::<RawCapellaOptimisticUpdate<U512>>(bytes)?.into_update()),
                n => Err(bad_size(n)),
            },
            Fork::Deneb => match sync_committee_size {
                32 => Ok(decode_as::<RawDenebOptimisticUpdate<U32>>(bytes)?.into_update()),
                512 => Ok(decode_as::<RawDenebOptimisticUpdate<U512>>(bytes)?.into_update()),
                n => Err(bad_size(n)),
            },
            Fork::Electra => match sync_committee_size {
                32 => Ok(decode_as::<RawElectraOptimisticUpdate<U32>>(bytes)?.into_update()),
                512 => Ok(decode_as::<RawElectraOptimisticUpdate<U512>>(bytes)?.into_update()),
                n => Err(bad_size(n)),
            },
        }
    }
}

#[derive(Decode)]
struct RawAltairOptimisticUpdate<N: Unsigned> {
    attested_header: AltairLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawAltairOptimisticUpdate<N> {
    fn into_update(self) -> LightClientOptimisticUpdate {
        LightClientOptimisticUpdate {
            attested_header: Altair(self.attested_header),
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        }
    }
}

#[derive(Decode)]
struct RawBellatrixOptimisticUpdate<N: Unsigned> {
    attested_header: BellatrixLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawBellatrixOptimisticUpdate<N> {
    fn into_update(self) -> LightClientOptimisticUpdate {
        LightClientOptimisticUpdate {
            attested_header: Bellatrix(self.attested_header),
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        }
    }
}

#[derive(Decode)]
struct RawCapellaOptimisticUpdate<N: Unsigned> {
    attested_header: CapellaLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawCapellaOptimisticUpdate<N> {
    fn into_update(self) -> LightClientOptimisticUpdate {
        LightClientOptimisticUpdate {
            attested_header: Capella(self.attested_header),
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        }
    }
}

#[derive(Decode)]
struct RawDenebOptimisticUpdate<N: Unsigned> {
    attested_header: DenebLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawDenebOptimisticUpdate<N> {
    fn into_update(self) -> LightClientOptimisticUpdate {
        LightClientOptimisticUpdate {
            attested_header: Deneb(self.attested_header),
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        }
    }
}

#[derive(Decode)]
struct RawElectraOptimisticUpdate<N: Unsigned> {
    attested_header: ElectraLightClientHeader,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawElectraOptimisticUpdate<N> {
    fn into_update(self) -> LightClientOptimisticUpdate {
        LightClientOptimisticUpdate {
            attested_header: Electra(self.attested_header),
            sync_aggregate: self.sync_aggregate.into_sync_aggregate(),
            signature_slot: self.signature_slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::chain_spec::Fork;
    use crate::types::consensus::LightClientOptimisticUpdate;

    #[test]
    fn rejects_bad_committee_size() {
        let err = LightClientOptimisticUpdate::from_ssz(&[], Fork::Altair, 64);
        assert!(err.is_err());
    }
}
