
# eBPF for Windows Flow Classification (Flow Maps)

## Contents

1. [Purpose](#purpose)
2. [Requirements](#requirements)
3. [Alternative - Using existing Linux hooks](#alternative---using-existing-linux-hooks)
4. [Design Overview](#design-overview)
5. [eBPF Design](#ebpf-design)
    - [Program Types](#program-types)
    - [Attach Types](#attach-types)
    - [Flow Map](#flow-map)
    - [Context Structure](#context-structure)
    - [Action / Verdict Model](#action--verdict-model)
    - [Helpers](#helpers)
    - [Datagram specifics](#datagram-specifics)
6. [Architecture](#architecture)
    - [Hook Integration and Flow](#hook-integration-and-flow)
    - [Lifecycle](#lifecycle)
7. [WFP Integration](#wfp-integration)
8. [Security and Access Control](#security-and-access-control)
9. [Verifier, ABI, and Versioning](#verifier-abi-and-versioning)
10. [Testing and Validation](#testing-and-validation)
11. [Linux Compatibility](#linux-compatibility)
12. [Roadmap and Phasing](#roadmap-and-phasing)
13. [Future Phases](#future-phases)
    - [Pending Flows (P2)](#pending-flows-p2)
    - [Re-authorization (P3)](#re-authorization-p3)
    - [Redirect (P4)](#redirect-p4)
14. [Open Questions](#open-questions)

> **Status:** Design proposal. Phase 1 (synchronous flow classification for TCP
> streams and datagrams) is described normatively. Phases 2-4 (pending flows,
> re-authorization, redirect) are described as forward-looking proposals and are
> explicitly marked as such. C type/enum/context/helper sketches are **proposed**
> and non-final. Statements about Windows Filtering Platform (WFP) behavior that
> have not yet been validated in code are flagged `[VERIFY]` or `[ASSUMED]`.

---

## Purpose

Provide an eBPF interface for classifying network **flows** by inspecting their
transport payload (TCP stream data and datagrams), and then allowing or blocking
the flow based on that inspection.

These hooks support security and observability solutions that need to parse
transport payloads without incurring per-packet overhead for flows that can be
ignored. The design is built around a **flow map**: an explicit, enumerable set
of the flows currently under classification. Membership in a flow map is what
arms payload inspection for a flow, mirroring the Linux `sockmap` model where map
membership drives inspection.

Unlike the Linux stream hooks, classification here is **whole-flow**: a program
inspects payload segments in order and reaches an allow/block decision about the
**connection**, rather than passing or dropping individual messages.

## Requirements

Phase 1 (normative):

- A way to choose, per flow, whether to classify that flow's transport payload.
- A hook that receives each transport payload segment in order, for both ingress
  and egress, for flows selected for classification.
  - Three synchronous actions:
    - **Allow** the flow and stop inspecting it (for the returning program).
    - **Block** the flow (no further inspection for the returning program).
    - **Need more data**: allow the current segment but keep inspecting.
- A way to clean up per-flow state when a flow is deleted while still being
  classified.
- No eBPF program is invoked for segments of flows not selected for
  classification.
- Multiple independent classifiers may inspect the same flow (see
  [Action / Verdict Model](#action--verdict-model)).
- Once a classifier allows or blocks a flow, it is no longer invoked for that
  flow (except for a final cleanup invocation on flow deletion).
- No payload mutation is required - only inline inspect / allow / block.
- The set of flows under classification is enumerable and inspectable from user
  mode.

Later phases add pending flows (asynchronous, user-mode-assisted decisions),
re-authorization of established flows, and redirect. Their requirements are
described in [Future Phases](#future-phases).

## Alternative - Using existing Linux hooks

Linux provides several relevant eBPF facilities:

- `BPF_MAP_TYPE_SOCKMAP` / `BPF_MAP_TYPE_SOCKHASH`: maps holding socket
  references. A socket added to such a map inherits the parser/verdict programs
  attached to the map; **map membership drives inspection**.
- `BPF_PROG_TYPE_SK_SKB` (`STREAM_PARSER`, `STREAM_VERDICT`, `SK_SKB_VERDICT`):
  stream parsing and per-message verdicts (`SK_PASS` / `SK_DROP`, plus redirect).
- `BPF_PROG_TYPE_SK_MSG`: egress message inspection.
- `BPF_PROG_TYPE_SOCK_OPS`: socket lifecycle callbacks (for example
  `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` / `PASSIVE_ESTABLISHED_CB`) used to add
  sockets to a sockmap via `bpf_sock_hash_update()`.

On Linux the required functionality can be approximated by combining these, but
there is no single, well-constrained hook for classifying a **flow** by
inspecting its stream data:

- The existing verdicts are **per message/segment** (pass/drop this message), not
  a whole-flow allow/block decision.
- Blocking a connection generally requires injecting a TCP RST, dropping messages
  until timeout, or redirecting to a dummy socket.
- Most hooks see traffic in only one direction.

This design adopts the Linux "membership drives inspection" concept but
re-shapes it around a Windows flow identity and a whole-flow verdict. See
[Linux Compatibility](#linux-compatibility) for the concept-by-concept mapping
and the deliberate divergences.

## Design Overview

The end-to-end model:

1. **Selection / enrollment.** A `sock_ops` program running at flow establishment
   decides whether a flow should be classified. To start classification it calls
   `bpf_flow_map_track()`, which records the flow in a **flow map**. The flow
   identity used to arm inspection is taken from the program's context (the WFP
   flow of the current invocation), not from caller-supplied bytes.
2. **Arming.** Inserting a flow into a flow map arms transport-payload inspection
   for that flow. Removing it (when allowed, blocked, or deleted) disarms it.
3. **Classification.** A **flow classify** program is attached to a flow map (the
   map is the program's attach parameter). When payload arrives for a tracked
   flow, the attached program is invoked with the segment/datagram and flow
   metadata, and returns a verdict.
4. **Verdict.** Verdicts are produced synchronously by the program's return value,
   or asynchronously by a user-mode write into the flow map entry. Both feed a
   single action model.
5. **Aggregation.** A flow may be tracked by multiple flow maps (each with its own
   classifier); the extension aggregates their verdicts.
6. **Teardown.** On flow deletion, still-classifying programs receive a final
   cleanup invocation and the flow's entries are removed.

The flow map is the center of gravity: it is the enumerable set of classified
flows, the per-flow state record, and the asynchronous action channel.

## eBPF Design

### Program Types

- **`EBPF_PROGRAM_TYPE_SOCK_OPS`** (existing) is reused for **enrollment**. A
  `sock_ops` program at flow establishment selects flows for classification by
  calling `bpf_flow_map_track()`. `sock_ops` already exposes the flow tuple and a
  WFP flow identifier (`bpf_sock_ops_get_flow_id`), and already receives
  connection established / deleted callbacks.
- **`EBPF_PROGRAM_TYPE_FLOW_CLASSIFY`** (new) is the **verdict** program type. A
  flow classify program is attached to a flow map and is invoked to inspect
  transport payload and classify the flow.

Enrollment and classification are intentionally different program types. In this
model they operate in different phases, and tail calls between them are not
required.

### Attach Types

Flow classify programs are **attached to a flow map** (map-attach): the flow map
is supplied as the program's attach parameter, and the core resolves and pins the
map for the lifetime of the attachment. This is the mechanism that binds a
classifier to the set of flows tracked in a given map.

Two attach types are defined under `EBPF_PROGRAM_TYPE_FLOW_CLASSIFY`:

- **`EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY`** - classification of TCP stream data.
- **`EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`** - classification of datagrams
  (UDP, ICMP, ICMPv6, raw).

At most **one** flow classify program is attached to a given flow map (per attach
type). Composition of multiple independent classifiers is achieved by tracking a
flow in **multiple** flow maps (see [Action / Verdict Model](#action--verdict-model)).

> `[ASSUMED]` Map-attach via a typed map attach parameter that the core resolves
> and pins is a new capability. The building blocks exist (opaque attach
> parameters, program-to-map association at load, program-held map references),
> but no attach type resolves a map attach parameter today; this is new core
> work to be validated.

### Flow Map

The flow map is a **custom map** registered by the network extension, using
`BPF_MAP_TYPE_HASH` as its base type.

- **Map type:** `BPF_MAP_TYPE_FLOW_MAP` (proposed id `17`).
- **Key:** caller-derived, supplied to `bpf_flow_map_track()`. The key defaults to
  the WFP flow identifier (`flow_id`) but may be any program-chosen value (for
  example a tuple or an application-specific id). The key only *labels* the entry;
  it confers no authority (arming is bound to the program's context - see
  [Security and Access Control](#security-and-access-control)). The program owns
  key uniqueness; the extension rejects a key already bound to a different live
  flow.
- **Value:** a per-flow record (below).

The entry is a **fixed header followed by a configurable per-flow scratch region**
(see [Per-flow storage](#per-flow-storage)). Proposed header layout (non-final).
Typed unions are used so that, depending on the flow type, a program reads the
correctly named and typed values rather than overloading a single field:

```c
typedef enum _ebpf_flow_classify_data_path
{
    EBPF_FLOW_CLASSIFY_DATA_PATH_STREAM,
    EBPF_FLOW_CLASSIFY_DATA_PATH_DATAGRAM,
} ebpf_flow_classify_data_path_t;

typedef enum _ebpf_flow_classify_metadata_flag
{
    EBPF_FLOW_CLASSIFY_METADATA_PORTS_VALID = 1 << 0,
    EBPF_FLOW_CLASSIFY_METADATA_ICMP_TYPE_CODE_VALID = 1 << 1,
} ebpf_flow_classify_metadata_flag_t;

typedef enum _ebpf_flow_state
{
    EBPF_FLOW_STATE_CLASSIFYING, ///< Under classification.
    EBPF_FLOW_STATE_PENDED,      ///< Awaiting an asynchronous decision (P2).
    EBPF_FLOW_STATE_ALLOWED,     ///< Allowed by this classifier.
    EBPF_FLOW_STATE_BLOCKED,     ///< Blocked (terminal).
    EBPF_FLOW_STATE_DELETED,     ///< Flow deleted while classifying (cleanup).
} ebpf_flow_state_t;

typedef struct _ebpf_flow_map_entry
{
    // Flow identity and metadata: extension-owned, read-only.
    uint64_t flow_id;                 ///< WFP flow identifier.
    uint32_t family;                  ///< AF_INET / AF_INET6.
    union
    {
        uint32_t local_ip4;
        uint32_t local_ip6[4];
    };
    union
    {
        uint32_t remote_ip4;
        uint32_t remote_ip6[4];
    };
    uint8_t protocol;
    uint32_t data_path;      ///< ebpf_flow_classify_data_path_t.
    uint32_t metadata_flags; ///< ebpf_flow_classify_metadata_flag_t bitmask.
    union
    {
        struct
        {
            uint16_t local_port;
            uint16_t remote_port;
        } ports; ///< Valid when METADATA_PORTS_VALID.
        struct
        {
            uint8_t type;
            uint8_t code;
        } icmp; ///< Valid when METADATA_ICMP_TYPE_CODE_VALID.
    } transport;
    uint32_t compartment_id;
    uint64_t interface_luid;
    uint8_t direction; ///< Flow direction.

    // Classification state: extension-managed.
    uint32_t state; ///< ebpf_flow_state_t.

    // Verdict: writable (asynchronous / user-mode channel).
    uint32_t action; ///< ebpf_flow_classify_action_t.

    // Reserved for future phases (redirect target reference, direction flag,
    // pend handle). Interpreted per action type when used.
    uint32_t action_flags;
    uint32_t reserved0;
    uint64_t reserved_ref;
    // The fixed header above is followed by a configurable per-flow scratch
    // region of (value_size - sizeof(header)) bytes (see "Per-flow storage").
} ebpf_flow_map_entry_header_t;
```

Field ownership (of the header):

- **Extension-owned, read-only** (to programs and user mode): `flow_id`, tuple and
  metadata, `data_path`, `metadata_flags`, `state`. These are populated by the
  extension when the flow is tracked and cannot be forged.
- **Writable:** `action` (the asynchronous verdict channel).
- **Reserved:** redirect and pend fields, used by later phases.

The entry does **not** carry a version/size header. The entry size is the map's
value size, and the header layout is determined by the extension version
negotiated through the program information. Field-level forward compatibility is
signaled by `metadata_flags` / `action_flags` and the reserved fields.

#### Per-flow storage

Most classifiers need to keep some state per flow (for example a parser state
machine or a byte accumulator), and the amount varies by program. This design
provides per-flow storage as a fixed part of the flow map entry - a **configurable
scratch region** immediately following the header, sized at map creation:
`value_size = sizeof(header) + N`, where `N >= 0` is chosen by the program (via its
map value type). The extension validates `value_size >= sizeof(header)` and manages
`N = value_size - sizeof(header)` scratch bytes per flow, freed automatically when
the flow is deleted.

Because the header is read-only and the scratch is read/write, and a verifier
cannot represent a read-only region immediately followed by a read/write region
inside one map value, **programs do not write the entry through a plain map value
pointer**. Instead the scratch is exposed as a bounded read/write region that the
verifier can track:

- **Primary:** the verdict program reads its persistent scratch through bounded
  `scratch_start` / `scratch_end` pointers in the [context](#context-structure)
  (mirroring `data_start` / `data_end`). `[VERIFY]` PREVAIL can bound a helper- or
  context-provided pointer by `value_size - sizeof(header)`; it already bounds
  `data` and map-value pointers, so this is expected to be feasible.
- **Complementary:** a helper (for example `bpf_flow_map_scratch()`) may return the
  same bounded read/write pointer, covering cases the context cannot (for example
  initializing scratch at enrollment). Header fields remain read-only because a
  writable pointer is only ever handed out for the scratch region.

User mode reads the header (metadata, `state`) and writes `action` through normal
map operations; the extension's update path keeps the header authoritative.

**Alternative (decoupled) storage model.** Linux keeps membership/verdict
(`sockmap` / `sockhash`) separate from per-object data
(`BPF_MAP_TYPE_SK_STORAGE`, "socket local storage"): `sk_storage` holds
program-defined `value_size` data per socket, accessed via
`bpf_sk_storage_get()` (a bounded read/write pointer, created on first access and
freed when the socket is destroyed). An equivalent decoupled model here would keep
the flow map fixed (header only) and add a separate **flow-local-storage** map (the
`sk_storage` analog) accessed through a `bpf_flow_storage_get()`-style helper, with
storage sized and managed independently and freed on flow deletion. This ports the
Linux model directly and removes the read-only/read-write layout concern from the
flow map, at the cost of a second map type and helper, and an extra
lookup/allocation per flow.

**Current leaning: the unified model** (configurable entry size). In the typical
case a classifier stores some state for **every** tracked flow, so co-locating it
with the entry is lower overhead (one entry, one allocation, one lookup per flow)
than a separate storage map, while still letting each program choose how much state
to keep. The decoupled `sk_storage`-style model is retained as an alternative and
may be preferable where per-flow data must be associated independently of
classification, or sized/managed separately.

### Context Structure

Flow classify programs receive a shared context, discriminated by `data_path`
(the same structure is used for stream and datagram):

```c
typedef struct _ebpf_flow_classify
{
    uint32_t family;
    union
    {
        uint32_t local_ip4;
        uint32_t local_ip6[4];
    };
    union
    {
        uint32_t remote_ip4;
        uint32_t remote_ip6[4];
    };
    uint8_t protocol;
    uint32_t compartment_id;
    uint64_t interface_luid;
    uint8_t direction; ///< Direction of the current segment/datagram.
    uint64_t flow_id;  ///< WFP flow identifier (also the default flow-map key).
    uint32_t data_path;      ///< ebpf_flow_classify_data_path_t.
    uint32_t metadata_flags; ///< ebpf_flow_classify_metadata_flag_t bitmask.
    union
    {
        struct
        {
            uint16_t local_port;
            uint16_t remote_port;
        } ports;
        struct
        {
            uint8_t type;
            uint8_t code;
        } icmp;
    } transport;
    uint32_t state;      ///< Current classification state (ebpf_flow_state_t).
    uint8_t* data_start; ///< Start of payload for this invocation.
    uint8_t* data_end;   ///< End of payload for this invocation.
    uint8_t* scratch_start; ///< Start of this flow's per-flow scratch (read/write).
    uint8_t* scratch_end;   ///< End of this flow's per-flow scratch (read/write).
} ebpf_flow_classify_t;
```

Notes:

- `data_start` / `data_end` are valid only for the duration of the invocation. For
  datagrams they bound one complete datagram payload.
- `scratch_start` / `scratch_end` bound this flow's persistent per-flow scratch (see
  [Per-flow storage](#per-flow-storage)); the region is read/write and persists
  across invocations for the life of the flow. Its size is
  `value_size - sizeof(header)` (zero when the map defines no scratch).
- The program does **not** write the flow map entry through a plain map value
  pointer (the header is read-only); it reads header fields from this context and
  reads/writes its scratch through the bounded scratch pointers. If a program needs
  to read another flow's entry, it may use a read-only `bpf_map_lookup_elem()`.
- The context is a fixed, verifier-checked layout (registered through the program
  information); it does not carry an inline version header.

### Action / Verdict Model

There is a single action enumeration, shared by the synchronous (program return)
and asynchronous (user-mode write) channels:

```c
typedef enum _ebpf_flow_classify_action
{
    EBPF_FLOW_CLASSIFY_ALLOW,          ///< Allow the flow; stop inspecting (this classifier).
    EBPF_FLOW_CLASSIFY_BLOCK,          ///< Block the flow (terminal).
    EBPF_FLOW_CLASSIFY_NEED_MORE_DATA, ///< Allow current segment; keep inspecting.
    EBPF_FLOW_CLASSIFY_PEND,           ///< Defer to an asynchronous decision (P2).
    EBPF_FLOW_CLASSIFY_REINVOKE,       ///< Re-run classification (P2 completion).
    EBPF_FLOW_CLASSIFY_REDIRECT,       ///< Redirect (reserved; P4).
} ebpf_flow_classify_action_t;
```

Production channels:

- **Inline (synchronous):** a flow classify program returns `ALLOW`, `BLOCK`,
  `NEED_MORE_DATA`, or (in P2) `PEND`. This is the fast path; it does not require a
  map write.
- **Asynchronous / user-mode:** a decision is written into the entry's `action`
  field (for example a pending flow's completion, or a re-authorization). The same
  action semantics and the same WFP application path apply, regardless of source.

Both channels converge on one application path. `REDIRECT` is reserved (verdict
programs cannot redirect - see [Redirect (P4)](#redirect-p4)). `REAUTH` and hard
revoke are control-plane operations (see [Re-authorization (P3)](#re-authorization-p3)).

**Whole-flow classification.** `NEED_MORE_DATA` permits the current segment and
continues inspection; `ALLOW` and `BLOCK` are decisions about the **connection**,
not the individual segment. This differs from Linux `SK_SKB`, whose verdict is
per message.

**One classifier per map; multiple maps per flow.** A flow map has a single
classifier. To run multiple independent classifiers over the same flow, the
enrollment program tracks the flow in multiple flow maps. Each map holds that
classifier's own entry (single-owner state). The extension **aggregates** across
the maps tracking a flow:

- `BLOCK` from any classifier is terminal for the flow.
- `ALLOW` finalizes that map's entry; other maps continue classifying.
- The flow is fully allowed (inspection disarmed) only when **all** tracking maps
  have allowed it.

This is a deliberate divergence from Linux, which errors if a socket is placed in
more than one program-bearing map. Allowing multiple maps per flow lets
independent solutions (for example a security agent and an observability agent)
classify the same flow without conflict.

### Helpers

Proposed helpers (BTF-resolved functions; signatures non-final):

```c
/**
 * @brief Track the flow of the current invocation in a flow map, arming
 *        transport-payload inspection for it.
 * @param[in] ctx    Current program context (identifies the WFP flow).
 * @param[in] map    Flow map to track the flow in.
 * @param[in] key    Flow-map key labeling the entry (default: the flow_id).
 * @param[in] flags  Reserved; must be 0.
 * @retval 0 on success, negative on failure.
 */
long bpf_flow_map_track(void* ctx, struct bpf_map* map, const void* key, uint64_t flags);

/**
 * @brief Get a bounded read/write pointer to the current flow's per-flow scratch
 *        in a flow map (complementary to the context scratch pointers).
 * @param[in] ctx  Current program context (identifies the flow).
 * @param[in] map  Flow map holding the flow's entry.
 * @return Pointer to (value_size - sizeof(header)) scratch bytes, or NULL.
 */
void* bpf_flow_map_scratch(void* ctx, struct bpf_map* map);
```

- `bpf_flow_map_track` is callable from the enrollment program (`sock_ops`). The
  flow identity used to arm inspection comes from `ctx`; a program can only arm its
  own flow.
- Flow classify programs read header fields from the context and read/write their
  per-flow scratch through the context scratch pointers or `bpf_flow_map_scratch`
  (never through a writable pointer to the entry header).
- Under the decoupled storage alternative
  ([Per-flow storage](#per-flow-storage)), a `bpf_flow_storage_get()`-style helper
  (the Linux `bpf_sk_storage_get` analog) would return per-flow storage from a
  separate flow-local-storage map instead.
- A redirect helper (`bpf_flow_redirect_map`) is reserved for P4.

### Datagram specifics

Datagram classification (`EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`) is part of
Phase 1 and shares the flow map, context, actions, and aggregation described
above. The datagram-only details:

- **Coverage:** connected, unconnected, and raw datagram flows - UDP, ICMP,
  ICMPv6, and raw.
- **One datagram per invocation:** each data invocation carries one complete
  datagram payload with boundaries preserved. IP fragment reassembly is not
  performed by eBPF programs. `[VERIFY]` complete-datagram delivery on every
  supported Windows release.
- **Payload range** (`data_start` / `data_end`) by protocol:
  - UDP and other recognized port-bearing transports: bytes after the transport
    header.
  - ICMP / ICMPv6: bytes after the base ICMP header.
  - Raw / unrecognized: bytes after the IP header.
- **Transport metadata:** `metadata_flags` selects the valid `transport` union
  member - `PORTS_VALID` for UDP (ports), `ICMP_TYPE_CODE_VALID` for ICMP
  (type/code), or neither for raw/unrecognized.
- Asynchronous pending (`PEND`) for datagrams is out of scope for Phase 1.

## Architecture

### Hook Integration and Flow

```
  new flow                       payload segment / datagram
     |                                     |
     v                                     v
 [sock_ops: flow established]        [flow classify program]
     |  bpf_flow_map_track(ctx,map,key)    |  inspect data_start..data_end
     v                                     v
 [flow map entry created] ---- arms --> [invoked only for tracked flows]
     |                                     |
     |                              returns ALLOW / BLOCK / NEED_MORE_DATA
     v                                     v
 [membership drives inspection]     [extension aggregates across maps]
```

1. At flow establishment, the enrollment (`sock_ops`) program decides whether to
   classify the flow and, if so, calls `bpf_flow_map_track()` for one or more flow
   maps.
2. Tracking arms transport-payload inspection for the flow.
3. For each payload segment/datagram of a tracked flow, the extension invokes the
   flow classify program attached to each tracking map and applies the aggregated
   verdict.
4. When the flow is allowed by all classifiers, blocked, or deleted, inspection is
   disarmed and the flow's entries are removed.

### Lifecycle

1. **Enroll / arm.** `bpf_flow_map_track()` inserts the flow into a flow map and
   arms inspection.
2. **Classify.** Payload invocations return `ALLOW` / `BLOCK` / `NEED_MORE_DATA`
   (or `PEND` in P2). Verdicts are aggregated across tracking maps.
3. **Finalize.** `ALLOW` finalizes a classifier's entry; `BLOCK` is terminal for
   the flow. When all classifiers have allowed (or one has blocked), inspection is
   disarmed.
4. **Delete.** On flow deletion, each still-classifying flow classify program is
   invoked once with `state = EBPF_FLOW_STATE_DELETED` (return value ignored) so it
   can clean up its own per-flow state. The extension then removes the flow's
   entries. The enrollment program may also observe teardown via the existing
   `sock_ops` connection-deleted callback.

## WFP Integration

This design is realized over the Windows Filtering Platform. The design-level
integration points (WFP implementation details are intentionally minimized here):

- **Enrollment** runs at the flow-established layer (where the `sock_ops` program
  already runs).
- **Stream classification** runs at the WFP stream layer.
- **Datagram classification** runs at the datagram-data layer.
- Tracking a flow associates a per-flow context and arms the corresponding
  data-layer callout so it is invoked **only** for tracked flows. Allowing (by all
  classifiers), blocking, or deleting a flow disarms it.
- A program receives a contiguous payload buffer valid for the invocation only.
- Verdicts map to WFP permit/block dispositions; a blocked flow's subsequent data
  is dropped.

The following WFP behaviors are assumptions to be validated during
implementation, not established facts:

- `[VERIFY]` Availability and semantics of a stream-layer callout suitable for
  in-order stream inspection.
- `[VERIFY]` Conditional-on-flow callout arming (invoking the data callout only
  for flows with an associated context).
- `[VERIFY]` One-complete-datagram-per-callback delivery, and datagram callout
  ordering relative to flow establishment, on every supported release.

## Security and Access Control

- **Arming is context-bound.** `bpf_flow_map_track()` arms the flow of the current
  invocation, taken from the program context. A program cannot arm a flow it is
  not handling. The map key is only a label and grants no authority.
- **Writing a verdict is authority.** In the unified action model, writing a flow
  map entry's `action` is equivalent to producing a WFP verdict. Write access to a
  flow map is therefore a security-sensitive capability, gated by possession of
  the map handle and by per-map-context identity: a client may only affect flows
  in maps it owns.
- **Control operations** (re-authorization, pending-flow subscription) require the
  map owner / appropriate privilege.
- **Identity and state cannot be forged.** Flow identity, tuple, metadata, and
  `state` are extension-owned and read-only; user mode can submit an `action` but
  cannot fabricate the flow record.
- **Captured payload** (pending flows, P2) is bounded, quota-limited, and readable
  only by the owning subscriber.
- **Sharing a flow map** (for example via a pin path) shares verdict authority and
  is an intentional, access-controlled capability.

## Verifier, ABI, and Versioning

- **Helpers** are exposed as BTF-resolved functions.
- **Context ABI:** `ebpf_flow_classify_t` is a fixed, verifier-checked layout
  registered through the program information's context descriptor. The verifier
  restricts a flow classify program's inline return value to the inline action
  subset (`ALLOW` / `BLOCK` / `NEED_MORE_DATA`, and `PEND` when enabled).
- **Map value versioning:** the entry has no inline header. Its size is the map's
  value size and its layout follows the negotiated extension version; optional
  fields are signaled by `metadata_flags` / `action_flags`. Growing the value
  changes the value size and is caught by the size check.
- **Boundary structures** that are versioned independently (program information /
  provider data, the pending-flow notification payload, and IOCTL request/response
  structures) carry a standard version+size header.
- **Version gating:** new map type and program information registration are
  additive. Any native-code (bpf2c) layout gate is set **above** the current
  product version (the product version is bumped accordingly).
- **Backward compatibility:** the change is additive; existing programs, maps, and
  attach types are unaffected.

## Testing and Validation

- **Unit (local):** flow-map custom-map operations (create / update / lookup /
  delete callbacks and value translation), action-to-WFP mapping, cross-map
  verdict aggregation, and verifier / program-information acceptance of the context
  and both attach types.
- **Fuzzing (local):** program-information / verifier coverage and the new context
  and helpers.
- **Socket / functional (VM):** stream (TCP) and datagram (UDP / ICMP / ICMPv6 /
  raw) classification end to end - enroll, arm, classify, allow / block /
  need-more-data; multiple classifiers (multiple maps) over one flow; cleanup on
  flow delete.
- **End to end (VM):** map-attach attach/detach, map pinning and lifetime, and
  one-classifier-per-map enforcement.
- **Stress (VM):** many concurrent tracked flows, high segment / datagram rate,
  arming/disarming churn, and map-full behavior.
- **WFP behavior validation (VM):** the `[VERIFY]` items in
  [WFP Integration](#wfp-integration) on every supported Windows release.

Tests that require a live network stack (socket, functional, end-to-end, and
stress) run on a virtual machine; unit, verifier, and fuzz tests run locally.

## Linux Compatibility

### Aligned (concepts adopted)

- **Membership drives inspection** (Linux `sockmap` / `sockhash`): tracking a flow
  in a flow map arms inspection.
- **Enrollment at establishment** (Linux `sock_ops` + `bpf_sock_hash_update`):
  reuse `sock_ops` + `bpf_flow_map_track`.
- **Per-segment stream inspection** (Linux `SK_SKB`) and **datagram inspection**
  (Linux `SK_MSG`).
- **Per-flow local storage** (Linux `BPF_MAP_TYPE_SK_STORAGE`, socket local
  storage): program-defined-size data associated with an object, accessed via a
  bounded read/write pointer and freed automatically on object teardown. Here it is
  the flow map's configurable scratch (or, in the decoupled alternative, a separate
  flow-local-storage map), freed on flow deletion. A flow may have storage in
  multiple maps, as a socket may in multiple `sk_storage` maps.

### Divergences (deliberate)

| Concept | Linux | This design |
|---|---|---|
| Program-to-map binding | `BPF_PROG_ATTACH` to a map fd | Typed map attach parameter, resolved and pinned by the core |
| Enrollment identity | Caller-chosen key; no integrity | Context-derived flow identity for arming (a program can only arm its own flow) |
| Map key | Program-chosen (a redirect lookup handle) | Caller-derived, defaulting to `flow_id` (a label, not authority) |
| Same flow in multiple program-bearing maps | Error | Allowed (multi-tenant classification) |
| Classifiers per map | One | One (relaxable later) |
| Verdict granularity | Per message (`SK_PASS` / `SK_DROP`) | Whole-flow allow/block informed by per-segment inspection |
| Redirect | Data-path `sk_redirect`, any time | Connect-time only (WFP), with a map+key target shape reserved |
| Membership vs per-flow data | Separate map types (`sockmap` vs `sk_storage`) | Leaning unified (one flow map: membership + verdict + configurable per-flow scratch); decoupled `sk_storage`-style model kept as an alternative |

**Portability.** The design pattern ports conceptually (membership drives
inspection), but the exact API differs: a classifier attaches to a map attach
parameter rather than being program-attached to a map fd; enrollment uses
`bpf_flow_map_track()` rather than `bpf_sock_hash_update()` with a chosen key; and
the flow is keyed by `flow_id` (or a re-derivable tuple). A Linux `sockmap`
program's structure carries over; its exact calls do not.

## Roadmap and Phasing

- **P1 - Synchronous flow classification (this document, normative).** Map-attach
  dispatch, `sock_ops` enrollment with `bpf_flow_map_track`, `BPF_MAP_TYPE_FLOW_MAP`,
  stream and datagram classifiers, inline `ALLOW` / `BLOCK` / `NEED_MORE_DATA`,
  multi-map aggregation, and membership-driven arming.
- **P2 - Pending flows.** Asynchronous, user-mode-assisted decisions.
- **P3 - Re-authorization.** Re-evaluate established flows; hard revoke.
- **P4 - Redirect.** Connect-time redirect via a socket map.

The reserved action values, reserved entry fields, and the socket-map concept
exist so that P2-P4 are additive.

## Future Phases

The following are forward-looking proposals, not normative for Phase 1. They are
included to show that the reserved extension points are sufficient.

### Pending Flows (P2)

Allow a classifier to defer a decision to user mode.

- **`PEND`** is an inline action. On pend, the extension captures the necessary
  state and **withholds** the current data (a true pend), then notifies user mode.
  - Withholding transport (stream) data risks stalling the peer if higher-level
    protocols are waiting on that data. This is mitigated by a bounded stale-pend
    watchdog and a systemwide pend-memory quota, and must be documented as a
    caution for classifiers that pend stream data.
- **Notification** is delivered by an extension-provided subscription: user mode
  subscribes (via an IOCTL) and receives a callback for each pended flow, in the
  style of the ring buffer / perf event array asynchronous callbacks. Because the
  extension drives notification, a program cannot accidentally drop a pended flow.
- **Completion** is a user-mode write of `action` (`ALLOW` / `BLOCK` / `REINVOKE`)
  into the flow map entry, keyed by the live flow. Completion reuses the flow map
  rather than a separate completion map.
- **Safety backstops:** systemwide pend-memory quota, stale-pend watchdog with a
  secure default (block), a re-invoke cap, exactly-once completion, and
  cross-client rejection via per-map-context identity.

### Re-authorization (P3)

Re-evaluate flows, including already-allowed ones, when policy changes.

- **Re-arm / data-driven.** Re-authorization re-arms targeted flows (they reappear
  in the flow map), so their subsequent data is re-classified. Scope is all tracked
  flows, a policy-defined set, or an explicit set of flows, initiated by a
  user-mode control operation (and/or a helper).
- **Hard revoke.** Immediate termination of a flow via the WFP flow-abort
  primitive. `[VERIFY]` the abort primitive takes the WFP flow handle.
- **Constraint.** Redirect cannot re-fire on re-authorization (the connect-redirect
  layer is not invoked on WFP re-authorization). Re-authorization can re-classify,
  re-arm, and revoke, but not redirect.
- `[VERIFY]` The WFP trigger mechanics for re-running enrollment on a policy change.
  The current extension does not invoke eBPF programs on WFP re-authorization, so
  re-authorization-driven re-classification is new behavior.

See also [Open Questions](#open-questions) for whether a data-less re-invoke is
also supported.

### Redirect (P4)

Connect-time redirect of flows.

- **Connect-time only.** WFP supports redirection only at the connect-redirect
  layer (before route selection); flow classify (stream/datagram) programs cannot
  redirect, so `REDIRECT` is reserved for them.
- **Target as a socket-map + key reference.** A redirect helper is shaped as
  `bpf_flow_redirect_map(ctx, socket_map, key, flags)` (mirroring Linux
  `bpf_*_redirect_map`), never a raw address, so that future post-establishment or
  data redirect is additive. A reserved socket map type (`BPF_MAP_TYPE_SOCK_MAP`)
  holds redirect targets, and an ingress/egress direction flag is reserved in
  `flags`.
- **Double-callout dedup.** Redirected connections fire the authorization callouts
  twice (original and redirected tuples); the design must deduplicate.
- Builds on the existing `sock_addr` connect-redirect mechanism rather than
  introducing a separate one.

## Open Questions

- **Re-authorization data-less re-invoke (P3).** In addition to the re-arm /
  data-driven model, should re-authorization support a **data-less re-invoke**? If
  so, is it a flow classify re-invoke, or a `sock_ops` (or similar) re-invoke that
  makes a fresh allow / block / need-more-data determination as at establishment?
- **Cross-map invocation order.** When multiple flow maps track one flow, define
  the order in which their classifiers are invoked (for example the order in which
  the flow began being tracked in each map).
- **Flow map bounds and per-flow storage size.** The `max_entries` and any
  systemwide bound on the number of concurrently tracked flows. Configurable
  per-flow scratch makes memory accounting more pointed: worst-case memory scales
  with `max_entries x (sizeof(header) + N)`, so a per-map and/or systemwide bound on
  scratch is needed.
- **Storage model.** Whether to keep the leaning **unified** model (configurable
  scratch in the flow map entry) or adopt the **decoupled** Linux `sk_storage`-style
  model (a separate flow-local-storage map). See
  [Per-flow storage](#per-flow-storage).
- **Scratch access mechanism.** Context `scratch_start`/`scratch_end` pointers, a
  `bpf_flow_map_scratch()` helper, or both; and `[VERIFY]` that PREVAIL can bound
  such a pointer by `value_size - sizeof(header)`.
