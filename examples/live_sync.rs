use eth_light_client::{
    types::primitives::ForkDigest, ChainSpec, Fork, LightClient, LightClientBootstrap,
    LightClientUpdate, Root,
};
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

fn process_sync_update_batch(
    client: &mut LightClient,
    mut bytes: &[u8],
    genesis_validators_root: Root,
) -> Result<(), Box<dyn std::error::Error>> {
    while !bytes.is_empty() {
        // Index guards
        if bytes.len() < 8 {
            return Err(format!("truncated chunk header: {} bytes remaining", bytes.len()).into());
        }
        let obj_len = u64::from_le_bytes(bytes[0..8].try_into()?) as usize;
        let chunk_len = 8 + obj_len;
        if obj_len < 4 || bytes.len() < chunk_len {
            return Err(format!(
                "invalid update chunk framing: declared {obj_len} bytes, {} remaining",
                bytes.len() - 8
            )
            .into());
        }

        let digest: ForkDigest = bytes[8..12].try_into()?;
        let fork = client
            .chain_spec()
            .fork_from_digest(digest, genesis_validators_root)
            .ok_or_else(|| {
                format!(
                    "ssz payload contains unsupported fork digest 0x{}",
                    hex::encode(digest)
                )
            })?;
        let ssz_obj_bytes = &bytes[12..chunk_len];
        let update = LightClientUpdate::from_ssz(
            ssz_obj_bytes,
            fork,
            client.chain_spec().sync_committee_size(),
        )?;
        let current_slot = current_slot_from_clock(client.chain_spec())?;
        client.process_light_client_update(update, current_slot)?;

        bytes = &bytes[chunk_len..];
    }

    Ok(())
}

fn current_slot_from_clock(chain_spec: &ChainSpec) -> Result<u64, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(chain_spec.timestamp_to_slot(timestamp))
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
