//! Command-line schema. Execution and rendering stay in the binary composition root.

use super::*;

#[derive(Debug, Parser)]
#[command(
    name = "ironet",
    version,
    about = "Create, join, and operate an ironet overlay network",
    long_about = "Create, join, and operate an ironet IP overlay network between Linux machines.\n\nA network contains nodes. Each node has an overlay address. An invite contains the network and peer information required by another machine to join. A node can also advertise subnets or forward overlay traffic between peers.\n\nSetup commands write the configuration and network state. The ironet daemon reads the configuration and provides the network interface. Runtime commands communicate with the daemon through its control socket.",
    after_help = "Common workflow:\n  ironet network create NAME\n  ironet invite create --address IP:PORT\n  ironet join INVITE\n\nInspect the network:\n  ironet network show\n  ironet node list\n  ironet status\n  ironet peers\n\nUse `ironet COMMAND --help` for command-specific behavior and examples. Use `--output json` or `--output jsonl` for machine-readable output."
)]
pub(crate) struct Cli {
    /// Path to the daemon configuration file.
    #[arg(
        short = 'c',
        long,
        global = true,
        env = "IRONET_CONFIG",
        default_value = "/etc/ironet/config.toml"
    )]
    pub(crate) config: PathBuf,
    /// Path to the daemon control socket.
    #[arg(
        long,
        global = true,
        env = "IRONET_SOCKET",
        default_value = DEFAULT_CONTROL_SOCKET
    )]
    pub(crate) socket: PathBuf,
    /// Directory containing network state and identity files.
    #[arg(
        long,
        global = true,
        env = "IRONET_STATE_DIR",
        default_value = "/var/lib/ironet"
    )]
    pub(crate) state_dir: PathBuf,
    /// Suppress informational logs; `health` also suppresses successful output.
    #[arg(short, long, global = true)]
    pub(crate) quiet: bool,
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Human,
    Json,
    #[value(alias = "ndjson")]
    Jsonl,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create, show, or leave a network.
    ///
    /// These commands manage the network configuration and the membership of this
    /// machine. Use `network create` once for the first node. Other machines use
    /// `join` with an invite.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Create, list, or revoke invites.
    ///
    /// The machine that created the network issues invites. Each invite is signed,
    /// expires at a fixed time, and identifies the node allowed to use it.
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
    /// Add this machine to an existing network by using an invite.
    ///
    /// The command validates the invite, writes the local configuration and identity,
    /// assigns an overlay address, and starts the service unless `--no-start` is set.
    /// With no invite argument on an interactive terminal, the command prompts for it.
    #[command(
        after_help = "Examples:\n  ironet join 'ironet://join/v2/...'\n  ironet join --invite-file invite.txt\n  cat invite.txt | ironet join --invite-file - --output json"
    )]
    Join {
        /// Invite URL; omit it to use `--invite-file` or the interactive prompt.
        #[arg(value_name = "INVITE")]
        invite: Option<String>,
        /// Read the invite URL from a file; use `-` to read standard input.
        #[arg(long, conflicts_with = "invite", value_name = "PATH")]
        invite_file: Option<PathBuf>,
        /// Set this node's name; the default is the machine hostname.
        #[arg(long, value_name = "NAME")]
        node_name: Option<String>,
        /// Reuse an identity retained by `network leave --keep-identity`.
        #[arg(long)]
        reuse_identity: bool,
        /// Write the configuration and state without starting the service.
        #[arg(long)]
        no_start: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// List nodes or change local node membership.
    ///
    /// `node list` combines local configuration with the daemon's current peer state.
    /// Rename and remove operations update this machine's configuration.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Manage subnets reachable through this node.
    ///
    /// Published subnets are advertised to other nodes as routes through this node.
    Subnet {
        #[command(subcommand)]
        command: SubnetCommand,
    },
    /// Control forwarding of overlay traffic between peers.
    ///
    /// Transit affects traffic received from one overlay peer and sent to another.
    /// Subnets reachable through this node are managed separately with `subnet`.
    Transit {
        #[command(subcommand)]
        command: TransitCommand,
    },
    /// Show the interface and address plan derived from the configuration.
    #[command(hide = true)]
    Inspect,
    /// Check reachability and round-trip time to an overlay address.
    ///
    /// Probes follow the same overlay route used for data traffic. The command returns
    /// a non-zero status when no probe reaches the destination.
    #[command(after_help = "Example:\n  ironet ping 10.42.0.8 --count 4 --timeout-ms 1000")]
    Ping {
        /// Destination IPv4 or IPv6 overlay address.
        #[arg(value_name = "ADDRESS")]
        target: IpAddr,
        /// Number of probes to send.
        #[arg(short = 'n', long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=20), value_name = "NUMBER")]
        count: u16,
        /// Timeout for each probe, in milliseconds.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=60_000), value_name = "MILLISECONDS")]
        timeout_ms: u64,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show peer connection state and path measurements.
    ///
    /// Output includes peer identity, connection state, selected transport, latency,
    /// loss, queue use, and packet counters from the daemon status.
    Peers {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show the node-by-node overlay path to an address.
    ///
    /// Each responding hop includes its overlay address, round-trip time, and node name
    /// when available. A timeout is reported for a hop that does not respond.
    #[command(after_help = "Example:\n  ironet trace 10.42.0.8 --max-hops 8 --timeout-ms 1000")]
    Trace {
        /// Destination IPv4 or IPv6 overlay address.
        #[arg(value_name = "ADDRESS")]
        target: IpAddr,
        /// Maximum number of overlay hops to inspect.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u8).range(1..=255), value_name = "NUMBER")]
        max_hops: u8,
        /// Timeout for each hop, in milliseconds.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=60_000), value_name = "MILLISECONDS")]
        timeout_ms: u64,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show the latest status published by the daemon.
    ///
    /// Status includes readiness, uptime, installed routes, peer connections, live QUIC
    /// path state, and V2 Cell/PacketTrain/FEC/Repair counters.
    Status {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
        /// Use JSON output; retained as an alias for `--output json`.
        #[arg(long)]
        json: bool,
    },
    /// Export the live V2 runtime snapshot in Prometheus text format.
    ///
    /// Every metric is derived from the same in-memory snapshot as `status` and
    /// uses the `ironet_v2_` namespace; no V1 metric aliases are emitted.
    Metrics,
    /// Open a terminal view of status, peers, routes, and diagnostics.
    ///
    /// The view reads daemon state repeatedly and does not change the configuration.
    #[command(visible_alias = "top")]
    Tui {
        /// Refresh interval, in milliseconds.
        #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(200..=60_000), value_name = "MILLISECONDS")]
        interval_ms: u64,
    },
    /// Check whether the daemon is ready.
    ///
    /// Exit status is zero only when daemon status is recent, required routes are
    /// installed, and configured peers are connected. Intended for service checks.
    Health,
    /// Reload a validated configuration in the running daemon.
    #[command(hide = true)]
    Reload,
    /// Validate the configuration, identity, routes, and local endpoint ID.
    #[command(hide = true)]
    Validate,
    /// Validate a configuration file and write its integrity digest.
    #[command(hide = true)]
    SealConfig,
    /// Install a validated configuration and retain the previous file.
    #[command(hide = true)]
    InstallConfig {
        /// Configuration file to validate and install.
        #[arg(long, value_name = "PATH")]
        source: PathBuf,
    },
    /// Replace the active configuration with its previous validated copy.
    #[command(hide = true)]
    RollbackConfig,
    /// Copy the node identity to a new file with mode 0600.
    #[command(hide = true)]
    BackupIdentity {
        /// Path for the new identity backup.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Restore an identity when the destination file does not exist.
    #[command(hide = true)]
    RestoreIdentity {
        /// Identity backup to restore.
        #[arg(long, value_name = "PATH")]
        source: PathBuf,
        /// Destination identity file.
        #[arg(
            long,
            default_value = "/var/lib/ironet/identity.key",
            value_name = "PATH"
        )]
        identity_file: PathBuf,
    },
    /// Check configuration, host requirements, and peer reachability.
    ///
    /// The command validates local files and system settings, then checks configured
    /// direct and relay addresses. It does not change configuration or network state.
    Doctor,
    /// Manage routes stored outside the main configuration file.
    ///
    /// Route changes update `routes.toml`. By default, changes are sent to the running
    /// daemon; use `--defer` to apply them during a later reload.
    #[command(hide = true)]
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// Generate signing keys and inspect, sign, or verify WASM policy packages.
    ///
    /// A policy package is a WebAssembly component carrying an `ironet.manifest.v1`
    /// custom section and, once signed, a trailing `ironet.signature.v1` section
    /// (Ed25519 over the BLAKE3 digest of the preceding bytes).
    #[command(
        after_help = "Examples:\n  ironet policy keygen --output signer.key\n  ironet policy sign --key signer.key unsigned.wasm --output policy.wasm\n  ironet policy inspect policy.wasm\n  ironet policy verify policy.wasm --signer-pubkey ed25519:...\n  ironet policy verify policy.wasm            # trust store from the sealed configuration"
    )]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    /// Generate an Ed25519 signing key and print its signer id and public key.
    ///
    /// The secret key is written with mode 0600; the public key is written next to it
    /// as `PATH.pub`.
    Keygen {
        /// Destination for the secret key.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// Signer id to print; defaults to the first 8 bytes of BLAKE3(public key).
        #[arg(long, value_name = "ID")]
        signer_id: Option<String>,
    },
    /// Show manifest, signer, digest, section table and file size.
    Inspect {
        /// Policy package (`.wasm`).
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a package against the sealed trust store or an explicit key/pin.
    ///
    /// Without `--signer-pubkey`/`--digest-pin` the `[autotune.wasm]` trust store of the
    /// configuration file (`--config`) is used.
    Verify {
        /// Policy package (`.wasm`).
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Accept signatures from this `ed25519:<hex|base32>` public key (repeatable).
        #[arg(long, value_name = "KEY")]
        signer_pubkey: Vec<String>,
        /// Accept an unsigned package with this `blake3:<hex>` digest (repeatable).
        #[arg(long, value_name = "DIGEST")]
        digest_pin: Vec<String>,
    },
    /// Sign a package; an existing signature is replaced.
    Sign {
        /// Secret key file written by `keygen`.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Unsigned (or previously signed) package.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Destination for the signed package.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// Signer id recorded in the signature; defaults to the key's signer id.
        #[arg(long, value_name = "ID")]
        signer_id: Option<String>,
        /// Attach (or replace) the manifest from this JSON file before signing.
        #[arg(long, value_name = "MANIFEST_JSON")]
        manifest: Option<PathBuf>,
    },
    /// Replay a policy over a recorded autotune tap fixture, offline and
    /// deterministic, through the production PolicyBackend/guardrail pipeline.
    ///
    /// POLICY is `builtin`, `native`, or an absolute path to a `.wasm`
    /// package. Replay intentionally runs `builtin` through the embedded
    /// `builtin.wasm` guest and verified loader for bit-exact parity checks;
    /// the daemon default instead uses the in-process CorePolicy. `native`
    /// selects conservative host rules. An external `.wasm` package is
    /// verified against the sealed trust store of `--config`, or against
    /// `--signer-pubkey`/`--digest-pin`.
    Replay {
        /// `builtin` replays the embedded guest; `native` uses conservative rules; or an absolute `.wasm` path.
        #[arg(value_name = "POLICY")]
        policy: String,
        /// Tap fixture: JSON array, profile summary, or JSONL; '-' reads stdin.
        #[arg(value_name = "FIXTURE")]
        fixture: PathBuf,
        /// Side selected from a profile summary's autotune_tap object.
        #[arg(long, default_value = "a")]
        side: String,
        /// Utility objective the host applies to the policy output.
        #[arg(long, value_enum, default_value_t = ReplayObjective::Balanced)]
        objective: ReplayObjective,
        /// Learner mode the policy runs in (`shadow` matches the checked-in
        /// golden fixtures).
        #[arg(long, value_enum, default_value_t = ReplayMode::Shadow)]
        mode: ReplayMode,
        /// Fixed deterministic seed for the policy pipeline.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Compare the run against a previously written report; exits non-zero
        /// on the first diverging sample (deterministic assert).
        #[arg(long, value_name = "REPORT_JSON")]
        golden: Option<PathBuf>,
        /// Report path; '-' writes stdout.
        #[arg(long, default_value = "-")]
        output: PathBuf,
        /// Accept `.wasm` signatures from this `ed25519:<hex|base32>` public
        /// key instead of the sealed trust store (repeatable).
        #[arg(long, value_name = "KEY")]
        signer_pubkey: Vec<String>,
        /// Accept an unsigned `.wasm` package with this `blake3:<hex>` digest
        /// (repeatable).
        #[arg(long, value_name = "DIGEST")]
        digest_pin: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ReplayObjective {
    Balanced,
    Throughput,
    Latency,
}

impl From<ReplayObjective> for ironet::protocol::v2::utility::Objective {
    fn from(value: ReplayObjective) -> Self {
        match value {
            ReplayObjective::Balanced => Self::Balanced,
            ReplayObjective::Throughput => Self::Throughput,
            ReplayObjective::Latency => Self::Latency,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ReplayMode {
    Off,
    Shadow,
    On,
}

impl From<ReplayMode> for ironet::protocol::v2::learner::LearnerModeV2 {
    fn from(value: ReplayMode) -> Self {
        match value {
            ReplayMode::Off => Self::Off,
            ReplayMode::Shadow => Self::Shadow,
            ReplayMode::On => Self::On,
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum NetworkCommand {
    /// Create a network and configure this machine as its first node.
    ///
    /// Writes the node identity, network state, daemon configuration, route file, and
    /// configuration digest. The IPv4/IPv6 address pools and node name use defaults when omitted.
    /// Starts the system service unless `--no-start` is set.
    #[command(
        after_help = "Examples:\n  ironet network create office\n  ironet network create office --node-name gateway-a --listen 203.0.113.10:4000\n  ironet network create lab --address-pool 10.42.0.0/16 --ipv6-address-pool fd42:6972:6f68::/64 --no-start --output json"
    )]
    Create {
        /// Name used to identify the network in local status and invites.
        #[arg(value_name = "NAME")]
        name: String,
        /// Set this node's name; the default is the machine hostname.
        #[arg(long, value_name = "NAME")]
        node_name: Option<String>,
        /// IPv4 CIDR used for overlay addresses; the default is selected automatically.
        #[arg(long, value_name = "CIDR")]
        address_pool: Option<ipnet::Ipv4Net>,
        /// IPv6 ULA CIDR used for overlay addresses; the default is selected automatically.
        #[arg(long, value_name = "CIDR")]
        ipv6_address_pool: Option<ipnet::Ipv6Net>,
        /// Add a Tailscale DERP server URL; repeat the option for multiple servers.
        #[arg(long = "derp-server", value_name = "URL")]
        derp_servers: Vec<String>,
        /// Bind one dual-stack UDP address.
        #[arg(long = "listen", value_name = "IP:PORT")]
        bind_address: Option<SocketAddr>,
        /// Override the embedded DNS suffix generated for this network.
        #[arg(long, value_name = "DOMAIN", conflicts_with = "no_dns")]
        dns_domain: Option<String>,
        /// Disable embedded authoritative DNS and host resolver integration.
        #[arg(long)]
        no_dns: bool,
        /// Reuse an identity retained by `network leave --keep-identity`.
        #[arg(long)]
        reuse_identity: bool,
        /// Write the configuration and state without starting the service.
        #[arg(long)]
        no_start: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show the network and this node's stored identity and address.
    ///
    /// Reads local configuration and network state. The daemon does not need to be
    /// running.
    Show {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Remove this machine's network configuration and state.
    ///
    /// Stops the service by default, then removes the configuration, digest, route
    /// file, network state, and keys. Use `--keep-identity` only when the same node
    /// identity must be reused later.
    #[command(
        after_help = "Examples:\n  ironet network leave --yes\n  ironet network leave --yes --keep-identity"
    )]
    Leave {
        /// Confirm removal of this machine's network files.
        #[arg(long)]
        yes: bool,
        /// Keep the node identity file for later reuse.
        #[arg(long)]
        keep_identity: bool,
        /// Leave service state unchanged before removing network files.
        #[arg(long)]
        no_stop: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum InviteCommand {
    /// Create an invite for one node to join the network.
    ///
    /// Only the machine that created the network has the signing key required for this
    /// command. The invite contains its expiry, the new node identity, network data,
    /// and bootstrap addresses. Creating an invite does not restart the daemon.
    #[command(
        after_help = "Examples:\n  ironet invite create\n  ironet invite create --expires 30m --address 203.0.113.10:4000\n  ironet invite create --address 192.0.2.10:4000 --address '[2001:db8::10]:4000' --output json"
    )]
    Create {
        /// Time before the invite expires, such as `30m`, `1h`, or `2d`.
        #[arg(long, default_value = "1h", value_name = "DURATION")]
        expires: String,
        /// Add an address that the joining node can use to reach this node.
        #[arg(long = "address", value_name = "IP:PORT")]
        addresses: Vec<SocketAddr>,
        /// Require an existing endpoint ID instead of generating a new node identity.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node_id: Option<EndpointId>,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// List invites issued by this machine.
    ///
    /// Shows each invite ID, expiry, and whether it has been revoked. Invite URLs are
    /// not stored and are therefore not included.
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Reject future connection attempts that use an invite ID.
    ///
    /// Revocation takes effect for subsequent connection handshakes. It does not
    /// interrupt a connection that is already active.
    Revoke {
        /// Invite ID shown by `invite create` or `invite list`.
        #[arg(value_name = "ID")]
        id: String,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum NodeCommand {
    /// List the local node, configured peers, and connected nodes.
    ///
    /// Local configuration is always shown. When the daemon is running, nodes learned
    /// from current peer connections are included.
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Change this node's name in the local configuration and network state.
    ///
    /// The endpoint ID and overlay address do not change. The running daemon is
    /// reloaded when available.
    Rename {
        /// New name for this node.
        #[arg(value_name = "NAME")]
        name: String,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Remove a node from this machine's peer and membership state.
    ///
    /// The selector may be a node name or endpoint ID. Removal blocks automatic
    /// admission of the same endpoint on this machine. The operation requires `--yes`.
    Remove {
        /// Node name or endpoint ID to remove.
        #[arg(value_name = "NODE")]
        node: String,
        /// Confirm the membership change.
        #[arg(long)]
        yes: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum SubnetCommand {
    /// Advertise a subnet as reachable through this node.
    ///
    /// The CIDR is added to this node's advertised prefixes. This command does not
    /// create routes or enable packet forwarding outside ironet.
    Publish {
        /// IPv4 or IPv6 subnet in CIDR notation.
        #[arg(value_name = "CIDR")]
        prefix: IpNet,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// List subnets advertised by this node.
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Stop advertising a subnet through this node.
    Unpublish {
        /// IPv4 or IPv6 subnet in CIDR notation.
        #[arg(value_name = "CIDR")]
        prefix: IpNet,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TransitCommand {
    /// Allow this node to forward overlay traffic between peers.
    ///
    /// Updates the local configuration and reloads the daemon when available.
    Enable {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Stop this node from forwarding overlay traffic between peers.
    ///
    /// Traffic addressed to this node and traffic for its published subnets are not
    /// changed by this setting.
    Disable {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RouteCommand {
    /// Add routes whose destination is reached through a peer.
    Add {
        /// One or more destination subnets in CIDR notation.
        #[arg(required = true, value_name = "PREFIX")]
        prefixes: Vec<IpNet>,
        /// Peer name or endpoint ID that owns the destination subnets.
        #[arg(long, value_name = "PEER_OR_ENDPOINT_ID")]
        owner: String,
        /// Validate and print the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save the change without sending it to the running daemon.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
    /// Import routes from TOML or `<endpoint-id> <prefix>...` text.
    Import {
        /// File to import; use `-` to read standard input.
        #[arg(value_name = "PATH")]
        source: PathBuf,
        /// Replace existing routes instead of merging imported routes.
        #[arg(long)]
        replace: bool,
        /// Validate and print the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save the change without sending it to the running daemon.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
    /// List routes stored in `routes.toml`.
    #[command(visible_alias = "ls")]
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Remove destination subnets or all routes owned by a peer.
    #[command(visible_alias = "rm")]
    Remove {
        /// CIDR, peer name, or endpoint ID to remove.
        #[arg(required = true, value_name = "PREFIX_OR_OWNER")]
        selectors: Vec<String>,
        /// Validate and print the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save the change without sending it to the running daemon.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
}
