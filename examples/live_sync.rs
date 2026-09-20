use std::{
    env::args,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use eth_light_client::{
    types::primitives::ForkDigest, ChainSpec, Fork, LightClient, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, LightClientUpdate, Root,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Note: This example is pinned to mainnet
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
    let (bytes, fork) = fetch_versioned_ssz(&url)?;
    let bootstrap = LightClientBootstrap::from_ssz(
        &bytes,
        fork,
        chain_spec.sync_committee_size(),
        genesis_validators_root,
    )?;

    // 3. Create light client
    let mut client = LightClient::new(chain_spec, trusted_block_root, bootstrap)?;

    loop {
        // 4. Bounded: trusted root's sync period -> current sync period
        catch_up(&mut client, &provider_url)?;

        // 5. Fetch and process finality update
        let url = format!("{provider_url}/eth/v1/beacon/light_client/finality_update");
        let (bytes, fork) = fetch_versioned_ssz(&url)?;
        let finality_update = LightClientFinalityUpdate::from_ssz(
            &bytes,
            fork,
            client.chain_spec().sync_committee_size(),
        )?;
        let current_slot = current_slot_from_clock(client.chain_spec())?;
        let finality_changes =
            client.process_light_client_update(finality_update.into(), current_slot)?;
        println!("finality update changes to store: {:?}", finality_changes);

        // 6. Fetch and process optimistic update
        let url = format!("{provider_url}/eth/v1/beacon/light_client/optimistic_update");
        let (bytes, fork) = fetch_versioned_ssz(&url)?;
        let optimistic_update = LightClientOptimisticUpdate::from_ssz(
            &bytes,
            fork,
            client.chain_spec().sync_committee_size(),
        )?;
        let current_slot = current_slot_from_clock(client.chain_spec())?;
        let optimistic_changes =
            client.process_light_client_update(optimistic_update.into(), current_slot)?;
        println!(
            "optimistic update changes to store: {:?}",
            optimistic_changes
        );

        thread::sleep(Duration::from_secs(12));
    }
}

/// Walks the store's verifiable frontier up to the current sync period
/// via `/updates` batches. Re-entered every tick: no-op when current;
/// recovery after a period rollover, machine suspend, or provider outage.
fn catch_up(
    client: &mut LightClient,
    provider_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut servable_period = max_servable_period(client);
    let current_slot = current_slot_from_clock(client.chain_spec())?;
    let mut current_sync_period = client
        .chain_spec()
        .slot_to_sync_committee_period(current_slot);

    while servable_period < current_sync_period {
        // Servers send, at max, 128 committee updates per response.
        let gap = (current_sync_period - servable_period).min(128);
        let url = format!("{provider_url}/eth/v1/beacon/light_client/updates?start_period={servable_period}&count={gap}");
        let bytes = ureq::get(&url)
            .header("Accept", "application/octet-stream")
            .call()?
            .body_mut()
            .read_to_vec()?;
        process_sync_update_batch(client, &bytes)?;

        let updated_servable_period = max_servable_period(client);
        if updated_servable_period == servable_period {
            return Err(format!("no progress from server at period {servable_period}").into());
        }
        servable_period = updated_servable_period;

        let current_slot = current_slot_from_clock(client.chain_spec())?;
        current_sync_period = client
            .chain_spec()
            .slot_to_sync_committee_period(current_slot);
    }

    Ok(())
}

/// Walks the `/updates` response with a shrinking cursor
fn process_sync_update_batch(
    client: &mut LightClient,
    mut bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    while !bytes.is_empty() {
        // Index guards
        if bytes.len() < 8 {
            return Err(format!("truncated chunk header: {} bytes remaining", bytes.len()).into());
        }
        let obj_len = usize::try_from(u64::from_le_bytes(bytes[0..8].try_into()?))?;
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
            .fork_from_digest(digest, client.genesis_validators_root())
            .ok_or_else(|| {
                format!(
                    "ssz payload contains unsupported fork digest 0x{}",
                    hex::encode(digest)
                )
            })?;
        let payload_bytes = &bytes[12..chunk_len];
        let update = LightClientUpdate::from_ssz(
            payload_bytes,
            fork,
            client.chain_spec().sync_committee_size(),
        )?;
        let current_slot = current_slot_from_clock(client.chain_spec())?;
        let changes = client.process_light_client_update(update, current_slot)?;
        println!("sync update changes to store: {:?}", changes);

        bytes = &bytes[chunk_len..];
    }

    Ok(())
}

fn fetch_versioned_ssz(url: &str) -> Result<(Vec<u8>, Fork), Box<dyn std::error::Error>> {
    let mut resp = ureq::get(url)
        .header("Accept", "application/octet-stream")
        .call()?;
    let bytes = resp.body_mut().read_to_vec()?;
    let fork = fork_from_version(
        resp.headers()
            .get("eth-consensus-version")
            .ok_or("missing Eth-Consensus-Version header")?
            .to_str()?,
    )?;

    Ok((bytes, fork))
}

fn fork_from_version(fork: &str) -> Result<Fork, String> {
    match fork {
        "altair" => Ok(Fork::Altair),
        "bellatrix" => Ok(Fork::Bellatrix),
        "capella" => Ok(Fork::Capella),
        "deneb" => Ok(Fork::Deneb),
        "electra" => Ok(Fork::Electra),
        "fulu" => Ok(Fork::Fulu),
        _ => Err(format!("unsupported fork: {}", fork)),
    }
}

fn current_slot_from_clock(chain_spec: &ChainSpec) -> Result<u64, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(chain_spec.timestamp_to_slot(timestamp))
}

/// Store contains sync committee at period P, and optionally the next
/// committee at P + 1
fn max_servable_period(client: &LightClient) -> u64 {
    client.current_sync_committee_period() + u64::from(client.next_sync_committee().is_some())
}
