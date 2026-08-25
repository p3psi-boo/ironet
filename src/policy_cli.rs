//! Policy package inspection, verification, signing, and deterministic replay.

use super::*;

pub(super) async fn policy_command(config_path: &Path, command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Keygen { output, signer_id } => policy_keygen(&output, signer_id),
        PolicyCommand::Inspect { file, json } => policy_inspect(&file, json),
        PolicyCommand::Verify {
            file,
            signer_pubkey,
            digest_pin,
        } => policy_verify(config_path, &file, &signer_pubkey, &digest_pin).await,
        PolicyCommand::Sign {
            key,
            file,
            output,
            signer_id,
            manifest,
        } => policy_sign(&key, &file, &output, signer_id, manifest.as_deref()),
        PolicyCommand::Replay {
            policy,
            fixture,
            side,
            objective,
            mode,
            seed,
            golden,
            output,
            signer_pubkey,
            digest_pin,
        } => {
            policy_replay(
                config_path,
                &policy,
                &fixture,
                &side,
                objective.into(),
                mode.into(),
                seed,
                golden.as_deref(),
                &output,
                &signer_pubkey,
                &digest_pin,
            )
            .await
        }
    }
}

fn policy_keygen(output: &Path, signer_id: Option<String>) -> Result<()> {
    ensure!(
        !output.exists(),
        "refusing to overwrite existing key {}",
        output.display()
    );
    let key = PolicySigningKey::generate()?;
    key.write_file(output)?;
    let public = key.public();
    let public_path = companion_path(output, ".pub");
    deployment::atomic_write(
        &public_path,
        format!("{}\n", public.encode()).as_bytes(),
        0o644,
    )?;
    let signer_id = signer_id.unwrap_or_else(|| public.default_signer_id());
    println!("signer_id = {signer_id}");
    println!("public_key = {public}");
    println!("key_file = {}", output.display());
    println!("public_key_file = {}", public_path.display());
    Ok(())
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_policy_package(file: &Path, limits: PackageLimits) -> Result<PolicyPackage> {
    let bytes =
        std::fs::read(file).with_context(|| format!("failed reading {}", file.display()))?;
    PolicyPackage::parse(&bytes, limits)
        .with_context(|| format!("{} is not a valid policy package", file.display()))
}

fn policy_inspect(file: &Path, json: bool) -> Result<()> {
    let package = read_policy_package(file, PackageLimits::default())?;
    if json {
        let value = serde_json::json!({
            "file": file.display().to_string(),
            "file_len": package.file_len,
            "body_len": package.body_len,
            "digest": package.digest_string(),
            "signed": package.signature.is_some(),
            "signer_id": package.signature.as_ref().map(|signature| signature.signer_id.clone()),
            "signature": package.signature,
            "manifest": package.manifest,
            "sections": package.sections,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let manifest = &package.manifest;
    println!("file = {}", file.display());
    println!("size = {} bytes", package.file_len);
    println!("signed_prefix = {} bytes", package.body_len);
    println!("digest = {}", package.digest_string());
    match &package.signature {
        Some(signature) => {
            println!("signed = true");
            println!("signer_id = {}", signature.signer_id);
            println!("signature_format = {}", signature.signature_format);
            println!("signature_digest = {}", signature.digest);
            println!("signature = {}", signature.signature);
        }
        None => println!("signed = false"),
    }
    println!("policy_id = {}", manifest.policy_id);
    println!("policy_version = {}", manifest.policy_version);
    println!("format_version = {}", manifest.format_version);
    println!("abi_world = {}", manifest.abi_world);
    println!(
        "extensions_supported = [{}]",
        join_numbers(&manifest.extensions_supported)
    );
    println!("state_schema = {}", manifest.state_schema);
    println!(
        "state_schema_accepts = [{}]",
        join_numbers(&manifest.state_schema_accepts)
    );
    println!("capabilities = [{}]", manifest.capabilities.join(", "));
    println!("minimum_host_version = {}", manifest.minimum_host_version);
    println!("maximum_state_bytes = {}", manifest.maximum_state_bytes);
    println!(
        "requested_memory_bytes = {}",
        manifest.requested_memory_bytes
    );
    println!("requested_fuel = {}", manifest.requested_fuel);
    println!("built_at = {}", manifest.built_at);
    println!("source_revision = {}", manifest.source_revision);
    println!("sections:");
    for (index, section) in package.sections.iter().enumerate() {
        println!(
            "  #{index} id={} kind={} name={:?} offset={} len={} payload_len={}",
            section.id,
            section.kind(),
            section.name.as_deref().unwrap_or("-"),
            section.offset,
            section.len,
            section.payload_len
        );
    }
    Ok(())
}

fn join_numbers<T: ToString>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

async fn policy_verify(
    config_path: &Path,
    file: &Path,
    signer_pubkeys: &[String],
    digest_pins: &[String],
) -> Result<()> {
    let (limits, mut trust, trust_source) = if signer_pubkeys.is_empty() && digest_pins.is_empty() {
        let config = Config::load(config_path).await?;
        let trust = TrustStoreV1::from_config(&config.autotune.wasm).with_context(|| {
            format!(
                "invalid [autotune.wasm] trust store in {}",
                config_path.display()
            )
        })?;
        (
            PackageLimits::from_config(&config.autotune.wasm),
            trust,
            format!("config {}", config_path.display()),
        )
    } else {
        let mut trust = TrustStoreV1::default();
        trust.require_signature = !signer_pubkeys.is_empty();
        for pin in digest_pins {
            trust.add_digest_pin(parse_digest(pin)?);
        }
        (PackageLimits::default(), trust, "command line".to_owned())
    };
    let package = read_policy_package(file, limits)?;
    // Explicit keys match whichever signer id the package claims, so that
    // `--signer-pubkey` answers "was this signed by that key?".
    let claimed_signer = package
        .signature
        .as_ref()
        .map(|signature| signature.signer_id.clone());
    for text in signer_pubkeys {
        let mut signer = TrustedSigner::new(PolicyPublicKey::parse(text)?);
        if let Some(signer_id) = &claimed_signer {
            signer = signer.with_signer_id(signer_id.clone());
        }
        if trust.signer(&signer.signer_id).is_none() {
            trust.add_signer(signer)?;
        }
    }
    match package.verify(&trust, chrono::Utc::now()) {
        Ok(verified) => {
            println!("verify = ok");
            println!(
                "trust = {}",
                match verified.trust {
                    TrustBasis::Signer => "signer",
                    TrustBasis::DigestPin => "digest_pin",
                }
            );
            println!("trust_source = {trust_source}");
            println!(
                "signer_id = {}",
                verified.signer_id.as_deref().unwrap_or("-")
            );
            println!("digest = {}", verified.digest_string());
            println!("policy_id = {}", verified.manifest.policy_id);
            println!("policy_version = {}", verified.manifest.policy_version);
            Ok(())
        }
        Err(error) => {
            println!("verify = failed");
            println!("trust_source = {trust_source}");
            println!("digest = {}", package.digest_string());
            println!("signer_id = {}", claimed_signer.as_deref().unwrap_or("-"));
            println!("reason = {error}");
            Err(anyhow::Error::new(error)
                .context(format!("{} failed verification", file.display())))
        }
    }
}

fn policy_sign(
    key_path: &Path,
    file: &Path,
    output: &Path,
    signer_id: Option<String>,
    manifest_path: Option<&Path>,
) -> Result<()> {
    let key = PolicySigningKey::read_file(key_path)?;
    let limits = PackageLimits::default();
    let mut bytes =
        std::fs::read(file).with_context(|| format!("failed reading {}", file.display()))?;
    if let Some(manifest_path) = manifest_path {
        let manifest_json = std::fs::read(manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?;
        let manifest = PolicyManifestV1::from_json(&manifest_json)
            .with_context(|| format!("invalid manifest {}", manifest_path.display()))?;
        bytes = policy_package::attach_manifest(&bytes, &manifest, limits)?;
    }
    let signer_id = signer_id.unwrap_or_else(|| key.public().default_signer_id());
    let signed = policy_package::sign(&bytes, &key, &signer_id, limits)?;
    deployment::atomic_write(output, &signed, 0o644)
        .with_context(|| format!("failed writing {}", output.display()))?;
    let package = PolicyPackage::parse(&signed, limits)?;
    println!("signed = {}", output.display());
    println!("signer_id = {signer_id}");
    println!("public_key = {}", key.public());
    println!("digest = {}", package.digest_string());
    println!("policy_id = {}", package.manifest.policy_id);
    println!("policy_version = {}", package.manifest.policy_version);
    println!("size = {} bytes", signed.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn policy_replay(
    config_path: &Path,
    policy: &str,
    fixture: &Path,
    side: &str,
    objective: Objective,
    mode: LearnerModeV2,
    seed: u64,
    golden: Option<&Path>,
    output: &Path,
    signer_pubkeys: &[String],
    digest_pins: &[String],
) -> Result<()> {
    let input = read_replay_source(fixture)?;
    let samples = decode_replay_samples(&input, side)?;
    let (slot, weights) = match policy {
        ironet::config::AUTOTUNE_POLICY_NATIVE => {
            // Explicit host-side conservative rules, with no learner.
            (PolicySlotV1::native_rules(), objective.weights())
        }
        ironet::config::AUTOTUNE_POLICY_BUILTIN => {
            // Replay intentionally exercises the embedded guest through the
            // verified loader. The daemon's default builtin path is instead
            // the in-process CorePolicy; this is the bit-exact parity path.
            let backend = PolicyLoader::new(PolicyEngine::try_new()?)
                .load_builtin(&ironet::config::AutotuneWasmConfig::default())
                .context("loading the embedded builtin policy component")?;
            let digest = backend
                .identity()
                .digest
                .map(|digest| encode_digest(&digest))
                .unwrap_or_default();
            (
                PolicySlotV1::new(Box::new(backend), None, digest),
                objective.weights(),
            )
        }
        selection if selection.to_ascii_lowercase().ends_with(".wasm") => {
            let path = Path::new(selection);
            ensure!(
                path.is_absolute(),
                "policy path must be absolute: {}",
                path.display()
            );
            let (config, trust) = if signer_pubkeys.is_empty() && digest_pins.is_empty() {
                let config = Config::load(config_path).await?;
                let trust =
                    TrustStoreV1::from_config(&config.autotune.wasm).with_context(|| {
                        format!(
                            "invalid [autotune.wasm] trust store in {}",
                            config_path.display()
                        )
                    })?;
                (config.autotune.wasm, trust)
            } else {
                let mut trust = TrustStoreV1::default();
                trust.require_signature = !signer_pubkeys.is_empty();
                for pin in digest_pins {
                    trust.add_digest_pin(parse_digest(pin)?);
                }
                for text in signer_pubkeys {
                    trust.add_signer(TrustedSigner::new(PolicyPublicKey::parse(text)?))?;
                }
                let config = ironet::config::AutotuneWasmConfig {
                    require_signature: trust.require_signature,
                    ..ironet::config::AutotuneWasmConfig::default()
                };
                (config, trust)
            };
            let backend = PolicyLoader::new(PolicyEngine::try_new()?)
                .load_from_path(path, &config, &trust, chrono::Utc::now())
                .with_context(|| format!("loading WASM policy {}", path.display()))?;
            let digest = backend
                .identity()
                .digest
                .map(|digest| encode_digest(&digest))
                .unwrap_or_default();
            (
                PolicySlotV1::new(Box::new(backend), None, digest),
                objective.weights(),
            )
        }
        selection => {
            let path = Path::new(selection);
            ensure!(
                path.is_absolute(),
                "policy path must be absolute: {}",
                path.display()
            );
            anyhow::bail!(
                "policy {} is not a .wasm component: external JSON policy artifacts were removed in Phase 6; deploy a signed .wasm component",
                path.display()
            );
        }
    };
    let report = replay_ticks(&samples, slot, weights, objective, mode, seed)?;
    if let Some(golden_path) = golden {
        let expected: TickReplayReportV2 = serde_json::from_str(&read_replay_source(golden_path)?)
            .with_context(|| format!("decoding golden report {}", golden_path.display()))?;
        if expected != report {
            let divergence = report
                .trace
                .iter()
                .zip(&expected.trace)
                .position(|(actual, expected)| actual != expected)
                .map(|index| format!("first diverging sample: {index}"));
            anyhow::bail!(
                "replay diverged from {} ({}; actual trace_digest {}, expected {})",
                golden_path.display(),
                divergence.as_deref().unwrap_or("report header differs"),
                report.trace_digest,
                expected.trace_digest
            );
        }
        println!(
            "golden = match ({} samples, trace_digest {})",
            report.samples, report.trace_digest
        );
    }
    let mut encoded = serde_json::to_vec_pretty(&report)?;
    encoded.push(b'\n');
    write_replay_output(output, &encoded)
}

fn read_replay_source(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut input = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
        Ok(input)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    }
}

fn decode_replay_samples(input: &str, side: &str) -> Result<Vec<ReplayTapSampleV2>> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input) {
        let selected = if let Some(samples) = value.as_array() {
            serde_json::Value::Array(samples.clone())
        } else if let Some(samples) = value.get("samples") {
            samples.clone()
        } else if let Some(samples) = value.get("autotune_tap").and_then(|tap| tap.get(side)) {
            samples.clone()
        } else {
            serde_json::Value::Array(vec![value])
        };
        return serde_json::from_value(selected).context("decoding replay samples");
    }

    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("decoding JSONL replay sample on line {}", index + 1))
        })
        .collect()
}

fn write_replay_output(path: &Path, bytes: &[u8]) -> Result<()> {
    if path == Path::new("-") {
        std::io::stdout().write_all(bytes)?;
    } else {
        std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}
