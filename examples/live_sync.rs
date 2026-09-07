use eth_light_client::{ChainSpec, Fork, LightClient, LightClientBootstrap, Root};
use std::{
    env::args,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // *Note*: this example is pinned to mainnet
    let chain_spec = ChainSpec::mainnet();
    let genesis_validators_root: Root =
        hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")?
            .try_into()
            .map_err(|_| "trusted block root must be 32 bytes")?;

    // 1. Client chooses a trusted block root and a data provider.
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
    let bootstrap_bytes = resp.body_mut().read_to_vec()?;
    let fork = fork_from_version(
        resp.headers()
            .get("eth-consensus-version")
            .ok_or("missing Eth-Consensus-Version header")?
            .to_str()?,
    )?;

    let bootstrap = LightClientBootstrap::from_ssz(
        &bootstrap_bytes,
        fork,
        chain_spec.sync_committee_size(),
        genesis_validators_root,
    )?;

    // 3. Create light client and time-related variables
    let mut client = LightClient::new(chain_spec, trusted_block_root, bootstrap)?;
    let current_slot = current_slot_from_clock(client.chain_spec())?;
    let mut store_sync_period = client.current_sync_committee_period();
    let mut current_sync_period = client
        .chain_spec()
        .slot_to_sync_committee_period(current_slot);

    // 4. Bounded loop: trusted root's sync period -> current sync period
    while store_sync_period < current_sync_period {
        // Servers send, at max, 128 committee updates per response.
        let gap = (current_sync_period - store_sync_period).min(128);
        let url = format!("{provider_url}/eth/v1/beacon/light_client/updates?start_period={store_sync_period}&count={gap}");

        let batch_bytes = ureq::get(&url)
            .header("Accept", "application/octet-stream")
            .call()?
            .body_mut()
            .read_to_vec()?;

        process_sync_update_batch(&mut client, &batch_bytes, genesis_validators_root)?;

        let new_period = client.current_sync_committee_period();
        if new_period == store_sync_period {
            return Err(format!("no progress from server at period {store_sync_period}").into());
        }
        store_sync_period = new_period;

        let current_slot = current_slot_from_clock(client.chain_spec())?;
        current_sync_period = client
            .chain_spec()
            .slot_to_sync_committee_period(current_slot);
    }

    // 5. Unbounded: live following
    loop {
        todo!()
    }
}

/// Walks a `/updates` response body: each chunk is
/// `length (LE u64) | fork_digest (4 bytes) | SSZ LightClientUpdate`,
/// decoded and fed to the client one chunk at a time.
fn process_sync_update_batch(
    _client: &mut LightClient,
    _bytes: &[u8],
    _genesis_validators_root: Root,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: shrinking-slice walk; digest -> fork mapping; decode + process per chunk
    todo!()
}

fn current_slot_from_clock(chain_spec: &ChainSpec) -> Result<u64, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(chain_spec.timestamp_to_slot(timestamp))
}

// TODO: Match against fork *digests*, not `Fork`
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
