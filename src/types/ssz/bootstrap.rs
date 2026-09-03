use super::{bad_size, decode_as, RawSyncCommittee};
use crate::chain_spec::Fork;
use crate::error::Result;
use crate::types::consensus::LightClientHeader::{Altair, Bellatrix, Capella, Deneb, Electra};
use crate::types::consensus::{
    AltairLightClientHeader, BellatrixLightClientHeader, CapellaLightClientHeader,
    DenebLightClientHeader, ElectraLightClientHeader, LightClientBootstrap,
};
use crate::types::primitives::Root;
use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U32, U5, U512, U6};
use ssz_types::FixedVector;

impl LightClientBootstrap {
    pub fn from_ssz(
        bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
        genesis_validators_root: Root,
    ) -> Result<LightClientBootstrap> {
        match fork {
            Fork::Altair => match sync_committee_size {
                32 => Ok(decode_as::<RawAltairLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawAltairLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Bellatrix => match sync_committee_size {
                32 => Ok(decode_as::<RawBellatrixLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawBellatrixLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Capella => match sync_committee_size {
                32 => Ok(decode_as::<RawCapellaLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawCapellaLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Deneb => match sync_committee_size {
                32 => Ok(decode_as::<RawDenebLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawDenebLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Electra => match sync_committee_size {
                32 => Ok(decode_as::<RawElectraLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawElectraLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
        }
    }
}

#[derive(Decode)]
struct RawAltairLightClientBootstrap<N: Unsigned> {
    header: AltairLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

impl<N: Unsigned> RawAltairLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Altair(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawBellatrixLightClientBootstrap<N: Unsigned> {
    header: BellatrixLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

impl<N: Unsigned> RawBellatrixLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Bellatrix(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawCapellaLightClientBootstrap<N: Unsigned> {
    header: CapellaLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
impl<N: Unsigned> RawCapellaLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Capella(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawDenebLightClientBootstrap<N: Unsigned> {
    header: DenebLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
impl<N: Unsigned> RawDenebLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Deneb(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawElectraLightClientBootstrap<N: Unsigned> {
    header: ElectraLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U6>,
}
impl<N: Unsigned> RawElectraLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Electra(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_committee_size() {
        let err = LightClientBootstrap::from_ssz(&[], Fork::Altair, 64, [0u8; 32]);
        assert!(err.is_err());
    }
}
