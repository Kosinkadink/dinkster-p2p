# dinkster-p2p

`dinkster-p2p` isolates libtorrent in a child process owned by one Dinkster server
and one AssetVault. The server launches it only while P2P downloading or
seeding is enabled. A private Unix socket is used on POSIX systems; Windows
uses authenticated loopback TCP.

The sidecar owns the vault's `.p2p` lock and persistent session state. It
accepts only closed, digest-bound download and seed leases from the host.
Version 2 LAN download leases may carry one native TCP peer endpoint, which the
sidecar revalidates against its active LAN policy before connecting. Exact
version 1 download leases and all version 1 seed leases remain accepted. LAN
sessions also use libtorrent's local service discovery (LSD) on active RFC 1918
interfaces. DHT, trackers, PEX, web seeds, uTP, UPnP, and NAT-PMP stay
disabled. A default-deny peer filter admits only addresses on those same
interfaces. The same session may open DHT, PEX, TCP, uTP, UPnP, NAT-PMP/PCP,
and approved trackers only while the scope is `lan-and-internet` and
a current global lease remains eligible. Returning to `lan-only`, revoking the
final lease, exhausting a seed budget, or reaching lease expiry removes global
handles and closes internet features without replacing the session or closing
LAN. Metered or unknown network policy closes only global handles and features;
LAN discovery and mappings stay active. Clearing that policy preserves the
global plan but requires explicit per-digest resume. The status reports these
closures through `sidecar.global.active` and `closureReason`; `networkPaused`
remains the all-P2P stop.
Each active listen address uses an explicit private-range port probed for both
TCP and UDP, including when uTP is disabled. Port selection tries at most 32
independently sampled candidates; native bind collisions permit at most four
handoffs per address and listener policy. Exhaustion closes that listener and
records a bounded status diagnostic without writing stderr or a log file.
Unchanged policy retains ports; all-P2P pause removes listeners without
replacing the session. Disabled startup performs no probes.

`GET /api/p2p/status` exposes `sidecar.diagnostics` through the existing status
permissions. It contains the latest 64 native peer, discovery-error, listener,
and upload observations, at most 32 observed listener bindings, and 68 latest
torrent upload samples. Events carry UTC and monotonic seconds for correlation.
Overwritten, omitted, malformed, and native alert-loss indicators distinguish
incomplete history from an absence of activity. History is in memory only and
is cleared when the native session closes; nothing is restored after restart.
Readers receive copies and cannot hold up alert processing with a slow sink.

Diagnostics contain canonical IP addresses, ports, content hashes, numeric
native error/operation/socket codes, and counters, never raw native messages,
paths, URLs, or credentials. Listener observations are not readiness or peer
authority. The pinned wheel lacks `lsd_peer_alert`; `lsdPeerEventsAvailable`
reports that limitation, so silence does not establish failed LSD reception.
No packet or verbose session logging is enabled. Upload samples compare native
`all_time_upload` and `total_payload_upload` with the per-digest LAN activity
record: `lanApplicationUploadedBytes` and `lanTransportUploadSample`. These LAN
fields exclude global accounting even for a global-owned native handle; they
are not the public transfer `uploadedBytes`, which also includes global totals.
Global-only traffic can therefore leave both LAN fields at zero. Native and
LAN samples can also differ in timing. Diagnostic collection does not query the
global counter database or replace progress or accounting counters.

Download-only leases expose no upload slots and stop on completion; continued
announcement requires a current seed grant.
The provider integration contract maps each current trusted-provider snapshot
through `authorized_global_leases` and applies it with
`P2PSidecarManager.reconcile_global`. Under that contract, local seed grants are
mapped automatically, while download leases require an explicitly requested
digest so catalog refresh does not prefetch provider assets. Declaration
disappearance or an observed tombstone revokes the prior lease in the same
reconciliation.
Subscribed resolver indexes supply these snapshots only when their
`trustedForP2P` flag is enabled. `licenseAuthoritative` identifies metadata
authority, not transfer eligibility. The resolver
v1 mapping ignores provider trackers and opens global transport with
trackerless DHT.

`P2PSessionPlan` is the single policy seam for the shared session. It separates
LAN availability from global DHT, tracker, PEX, TCP, uTP, and NAT features.
Applying `plan.close_global()` to the existing sidecar closes every internet
feature and restores the LAN peer filter without replacing the session or
disabling LAN LSD. TCP is session-wide, so a plan that keeps LAN active requires
global TCP whenever any internet feature is active. HTTP fallback remains
outside the sidecar in `TransportResolver`, whose explicit `global-p2p` slot
ranks after preferred-region HTTP and before other healthy HTTP sources.

The `p2p` settings category is the only enable boundary. Both
`downloadsEnabled` and `seedingEnabled` default to false with
`scope=lan-and-internet`; saved choices remain authoritative. Use
`dinkster-serve --disable-p2p` to start disabled without changing saved settings.
Constructing a disabled host manager creates no directory, process, socket,
or peer port. The host launches one sidecar when either capability becomes true and stops it
when both return to false. Runtime settings writes still require the ordinary
server category grant and `settings:write` capability.

`stagingBudgetBytes` defaults to 64 GiB and limits aggregate P2P download
reservations across LAN and Internet. Sparse holes still reserve their missing
allocation; existing partials count, but published assets and seed files do not.
Zero refuses new downloads. Lowering the budget pauses downloads that no longer
fit without deleting their bytes or pausing LAN seeds. Increasing it does not
automatically resume them. This is admission control, not a filesystem quota:
native in-flight writes, allocation granularity, and resume metadata can exceed
the setting before the next reconciliation pauses growth.

The host grants LAN work through the closed v1 `grant-download` and `grant-seed`
lease contracts. Global work uses an additive `grant-global` authorization
envelope so provider trackers do not change the persisted v1 lease schema. The
host can `revoke`, apply global or metered-network pauses,
control individual digests, `save-state`, and query `status`. Digest controls
cover pause, resume, stop, partial removal, budget reset, and continuous
seeding. A policy-paused transfer stays inactive until an explicit resume;
resetting a budget or selecting continuous seeding only changes the policy.
Download partials are confined below `<vault>/.p2p/staging` and record only
hash-verified, flushed pieces as durable progress. Completed safetensors and
GGUF files must pass their exact BitTorrent v2 descriptor, size, BLAKE3 digest,
and safe-format policy before atomic publication. Seed leases require an
authorized absolute regular file, the same full verification, and one or more
source grant IDs.
The shared `lease-status` command covers LAN and global leases. Global native
piece verification reports `verifiedBytes` for progress without claiming disk
durability. Only successful vault adoption reports a completed path and durable
size; adoption failures report a terminal failure instead of an inactive lease.
Global leases expire within six hours. Internet transfer totals,
ratio-equivalent seeding credits, and active seed time are monotonic SQLite
counters, so seeding budgets survive sidecar restarts. Byte totals and rates
exclude traffic observed to connected LAN peers. Bytes that cannot be attributed
when a peer disconnects between samples are charged to the internet budget, so
the budget can be conservatively consumed but never evaded.
Each session-state and libtorrent-resume file is replaced atomically. Malformed
state is quarantined and the replacement session starts paused with no leases.
Per-digest controls, cumulative byte counters, and the seed grant IDs needed to
report later revocation survive sidecar restarts. The host resolves those IDs
against the current canonical `P2PGrantSnapshot`; the sidecar does not create a
second grant or receipt authority. State versions before 4 drop seed leases
with legacy noncanonical grant IDs without discarding their activity records.
Restored leases remain inactive until the host revalidates and regrants them.

The server advertises `_dinkster-p2p._tcp.local.` only while it has an active
seed lease. Its HTTP endpoint accepts only
`GET /dinkster-p2p/v1/mappings/{blake3-digest}` and returns exactly `version`, `digest`,
`sizeBytes`, and `descriptor`; it has no list endpoint. Mapping results are
accepted only when they match a current trusted declaration. Declarative
resolver subscriptions remain HTTP-only unless `trustedForP2P` is set;
trusted-provider enumeration then supplies seed evidence. Resolver order is
local vault, LAN P2P, preferred-region healthy HTTP, global P2P, remaining
healthy HTTP, degraded HTTP, then broken HTTP. Discovery and transfer stalls
are bounded, and only one writer may materialize a digest in a vault at a time.
Mapping discovery continues watching for new peers while probing cached peers
within the same deadline, so an unrelated or stalled peer cannot hide a later
announcement of the requested digest.

On POSIX the IPC socket lives in a mode-0700 temporary directory. Windows uses
loopback TCP authenticated with a one-time 256-bit token inherited through the
child environment. A vault lock rejects a second owner. Unexpected exits use
at most three restarts in a 60-second window; the host HTTP server remains
independent and reports the terminal failure through `/api/p2p/status`.

The runtime artifact is pinned to `libtorrent==2.1.1`. Linux x86-64/AArch64,
Windows AMD64, and macOS ARM64 wheels for CPython 3.12 and 3.13 are recorded
in `dinkster_p2p.artifacts`; unsupported runtime combinations fail before a
session opens a listening socket.
