use eth_light_client::{ChainSpec, Fork, LightClient, LightClientBootstrap, Root};
use std::{
    env::args,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Define necessary variables. *Note*: this example is pinned to mainnet
    let chain_spec = ChainSpec::mainnet();
    let genesis_validators_root: Root =
        hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")?
            .try_into()
            .map_err(|_| "trusted block root must be 32 bytes")?;

    // Trusted block root and upstream server are supplied by the user
    let mut args = args().skip(1);
    let provider_url = args
        .next()
        .ok_or("usage: live_sync <provider-url> <trusted-block-root>")?;
    let root_hex = args
        .next()
        .ok_or("usage: live_sync <provider-url> <trusted-block-root>")?;
    let trusted_block_root: Root = hex::decode(root_hex.strip_prefix("0x").unwrap_or(&root_hex))?
        .try_into()
        .map_err(|_| "trusted block root must be 32 bytes")?;

    // 2. Fetch the bootstrap anchored to the trusted root
    let url = format!(
        "{provider_url}/eth/v1/beacon/light_client/bootstrap/0x{}",
        hex::encode(trusted_block_root)
    );
    let mut resp = ureq::get(&url)
        .header("Accept", "application/octet-stream")
        .call()?;
    let fork = fork_from_version(
        resp.headers()
            .get("eth-consensus-version")
            .ok_or("missing Eth-Consensus-Version header")?
            .to_str()?,
    )?;
    let bootstrap_bytes = resp.body_mut().read_to_vec()?;

    let bootstrap = LightClientBootstrap::from_ssz(
        &bootstrap_bytes,
        fork,
        chain_spec.sync_committee_size(),
        genesis_validators_root,
    )?;

    // 3. Create light client and clock
    let client = LightClient::new(chain_spec, trusted_block_root, bootstrap)?;
    let mut store_sync_period = client.current_sync_committee_period();
    let timestamp_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let current_slot = client.chain_spec().timestamp_to_slot(timestamp_secs);
    let current_sync_period = client
        .chain_spec()
        .slot_to_sync_committee_period(current_slot);

    // 4. Bounded loop: checkpoint's sync period -> current sync period
    while current_sync_period > store_sync_period {
        // Fetch next_sync_committee update

        store_sync_period += 1;
    }

    // 5. Unbounded: live following
    loop {
        todo!()
    }
}

fn fork_from_version(fork: &str) -> Result<Fork, String> {
    match fork {
        "altair" => Ok(Fork::Altair),
        "bellatrix" => Ok(Fork::Bellatrix),
        "capella" => Ok(Fork::Capella),
        "deneb" => Ok(Fork::Deneb),
        "electra" => Ok(Fork::Electra),
        _ => Err(format!("unsupported fork: {}", fork)),
    }
}
