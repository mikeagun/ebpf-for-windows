# eBPF for Windows Flow Classification Hook Design

## Contents

1. [Status](#status)
2. [Purpose](#purpose)
3. [Design overview](#design-overview)
4. [Relationship to Linux](#relationship-to-linux)
5. [eBPF interface](#ebpf-interface)
   - [Program and attach types](#program-and-attach-types)
   - [Flow map](#flow-map)
   - [Program attachment](#program-attachment)
   - [Flow enrollment](#flow-enrollment)
   - [Classification context](#classification-context)
   - [Payload access](#payload-access)
   - [Actions and classifier composition](#actions-and-classifier-composition)
6. [Lifecycle](#lifecycle)
7. [Stream and datagram behavior](#stream-and-datagram-behavior)
8. [WFP integration](#wfp-integration)
9. [Pending flows](#pending-flows)
10. [Security and resource management](#security-and-resource-management)
11. [Verifier, ABI, and versioning](#verifier-abi-and-versioning)
12. [Validation](#validation)
13. [Implementation phases](#implementation-phases)

## Status

This is a design proposal. The authoritative behavioral requirements are in
[FlowClassifyHookRequirements.md](FlowClassifyHookRequirements.md).

This design covers TCP stream data, UDP datagrams, and non-error ICMP and ICMPv6 messages. Implementation is staged:
TCP stream classification precedes datagram classification.

`PEND` withholds the current payload for an external decision. Its implementation is deferred to a separate phase.

Payload mutation, raw IP datagrams, ICMP error layers, reauthorization, and redirect are out of scope.

All type and function declarations below are proposed and non-final.

## Purpose

The flow classification hook lets eBPF programs inspect transport payload and make a policy decision for the associated
network flow.

A **network flow** is traffic with common endpoint and protocol metadata tracked under one stable identifier and
lifecycle. TCP flows are connections. Related UDP datagrams and ICMP or ICMPv6 messages are grouped under the same flow
identifier.

**Flow classification** is a whole-flow decision informed by metadata and payload inspection. `ALLOW` and `BLOCK` are
terminal decisions for a classifier or flow, not per-packet verdicts. A classifier can return `NEED_MORE_DATA` to
permit the current payload and continue observing future payload.

## Design overview

The design follows the Linux sockmap principle that map membership drives inspection:

1. A flow-classify program attaches to a **flow map**.
2. An existing `sock_ops` program runs at flow establishment and decides whether the current flow needs payload
   inspection.
3. The `sock_ops` program calls `bpf_flow_map_track()` for each classifier map that should inspect the flow.
4. Membership in a flow map activates that map's classifier for the flow.
5. On each applicable payload indication, the extension invokes active classifiers in global program-attachment order.
6. `ALLOW` removes only the returning classifier's membership. `NEED_MORE_DATA` keeps that classifier active.
   `BLOCK` is terminal for the flow.
7. When no active classifier remains, payload inspection is disarmed.

```text
 flow established                           payload indication
       |                                            |
       v                                            v
 [sock_ops program]                         [extension flow state]
       | bpf_flow_map_track()                       |
       v                                            v
 [flow map membership] ---- activates ----> [classifiers in attach order]
                                                    |
                                       ALLOW / BLOCK / NEED_MORE_DATA
```

One flow may be tracked by multiple flow maps so independent products or policy components can classify it. Each flow
map supports at most one program per flow-classification attach type.

## Relationship to Linux

Linux combines `BPF_PROG_TYPE_SOCK_OPS` enrollment with programs attached to `BPF_MAP_TYPE_SOCKMAP` or
`BPF_MAP_TYPE_SOCKHASH`. Sockets inserted into the map inherit its parser or verdict programs.

This design adopts:

- `sock_ops` enrollment at flow establishment;
- program attachment to a map FD;
- membership-driven payload inspection;
- direct payload access with lazy linearization.

It deliberately differs from Linux:

- the map key is a Windows flow ID rather than a caller-selected socket lookup key;
- verdicts classify a whole flow rather than one message;
- one flow may be tracked by multiple classifier maps;
- flow direction selection is explicit rather than implied by program type;
- asynchronous pending uses Windows-specific payload retention and reinjection.

## eBPF interface

### Program and attach types

The design reuses `EBPF_PROGRAM_TYPE_SOCK_OPS` for enrollment and adds:

- `EBPF_PROGRAM_TYPE_FLOW_CLASSIFY`
- `EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY`
- `EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`

The context and flow-map value contain fields used by both stream and datagram classification. The TCP phase registers
`EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY`; the datagram phase registers
`EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY`.

### Flow map

`BPF_MAP_TYPE_FLOW_MAP` is a custom map provided by `netebpfext`, backed by a hash map.

Map creation requires a `uint64_t` key, the exact fixed metadata value size for the negotiated ABI, and a nonzero
`max_entries`.

#### Key

The key is the stable `uint64_t flow_id` supplied by WFP and exposed by
`bpf_sock_ops_get_flow_id()`.

#### Value

The value is fixed-size, extension-owned metadata. A proposed shape is:

```c
/**
 * @brief Identifies the payload path used to classify a flow.
 */
typedef enum _ebpf_flow_classify_data_path
{
    EBPF_FLOW_CLASSIFY_DATA_PATH_STREAM,   /**< TCP stream payload. */
    EBPF_FLOW_CLASSIFY_DATA_PATH_DATAGRAM, /**< UDP, ICMP, or ICMPv6 message payload. */
} ebpf_flow_classify_data_path_t;

/**
 * @brief Indicates which optional flow metadata fields are valid.
 */
typedef enum _ebpf_flow_classify_metadata_flag
{
    EBPF_FLOW_CLASSIFY_METADATA_PORTS_VALID = 1 << 0, /**< The TCP or UDP ports are valid. */
    EBPF_FLOW_CLASSIFY_METADATA_ICMP_TYPE_CODE_VALID = 1 << 1, /**< The ICMP type and code are valid. */
    EBPF_FLOW_CLASSIFY_METADATA_PROCESS_ID_VALID = 1 << 2, /**< The process identifier is valid. */
    EBPF_FLOW_CLASSIFY_METADATA_LOGON_ID_VALID = 1 << 3, /**< The logon identifier is valid. */
    EBPF_FLOW_CLASSIFY_METADATA_ADMIN_VALID = 1 << 4, /**< The administrator status is valid. */
} ebpf_flow_classify_metadata_flag_t;

/**
 * @brief Identifies one or both payload directions.
 */
typedef enum _ebpf_flow_direction
{
    EBPF_FLOW_DIRECTION_INBOUND = 1 << 0,  /**< Inbound payload. */
    EBPF_FLOW_DIRECTION_OUTBOUND = 1 << 1, /**< Outbound payload. */
    EBPF_FLOW_DIRECTION_BOTH = 0x3,        /**< Inbound and outbound payload. */
} ebpf_flow_direction_t;

/**
 * @brief Contains extension-owned metadata for one tracked flow.
 *
 * User mode can read this value, but neither user mode nor eBPF programs can modify it through standard map
 * operations.
 */
typedef struct _ebpf_flow_map_value
{
    uint64_t flow_id; /**< Stable WFP flow identifier and flow-map key. */
    uint32_t family;  /**< IP address family. */
    union
    {
        uint32_t local_ip4;    /**< Local IPv4 address in network byte order. */
        uint32_t local_ip6[4]; /**< Local IPv6 address in network byte order. */
    };
    union
    {
        uint32_t remote_ip4;    /**< Remote IPv4 address in network byte order. */
        uint32_t remote_ip6[4]; /**< Remote IPv6 address in network byte order. */
    };
    uint32_t protocol;       /**< IP protocol number. */
    uint32_t data_path;      /**< One ebpf_flow_classify_data_path_t value. */
    uint32_t metadata_flags; /**< Bitmask of ebpf_flow_classify_metadata_flag_t values. */
    union
    {
        struct
        {
            uint16_t local_port;  /**< Local TCP or UDP port in network byte order. */
            uint16_t remote_port; /**< Remote TCP or UDP port in network byte order. */
        } ports;                   /**< Port metadata when EBPF_FLOW_CLASSIFY_METADATA_PORTS_VALID is set. */
        struct
        {
            uint8_t type; /**< ICMP or ICMPv6 message type. */
            uint8_t code; /**< ICMP or ICMPv6 message code. */
        } icmp;           /**< ICMP metadata when EBPF_FLOW_CLASSIFY_METADATA_ICMP_TYPE_CODE_VALID is set. */
    } transport; /**< Protocol-specific transport metadata. */
    uint32_t compartment_id;  /**< Network compartment identifier. */
    uint64_t interface_luid;  /**< Local interface LUID. */
    uint64_t process_id;      /**< Initiating process identifier, if valid. */
    uint64_t logon_id;        /**< Initiating logon identifier, if valid. */
    int32_t is_admin;         /**< 1 for an administrator, 0 otherwise, or -1 when unavailable. */
    uint32_t armed_directions; /**< Bitmask of ebpf_flow_direction_t values selected for this membership. */
} ebpf_flow_map_value_t;
```

The value does not contain a verdict, pending state, retained payload, writable scratch, or WFP pointers. Classifiers
store mutable parser or policy state in ordinary program maps keyed by `flow_id`.

#### Operations

- User mode can enumerate keys and look up copied metadata values.
- User-mode update and delete are rejected.
- eBPF map lookup, update, and delete helpers are rejected for this map type.
- Membership is created only by `bpf_flow_map_track()`.
- Membership is removed only by classifier verdict or lifecycle processing.

The map's `max_entries` bounds the number of active classifier memberships across stream and datagram flows.

### Program attachment

A flow-classify program attaches to a flow-map FD through the normal link model:

```c
bpf_prog_attach(program_fd, flow_map_fd, attach_type, 0);
```

eBPF core resolves and validates the map FD in the attaching process, holds a map reference in the link, and passes the
map's provider context to `netebpfext`. Only the resolved map reference is retained after the attach operation.

A flow map supports:

- zero or one stream classifier; and
- zero or one datagram classifier.

A second program for an occupied attach type is rejected. Multiple classifiers of the same type use separate flow
maps.

Every successful link receives a monotonically increasing global attachment sequence. Applicable classifiers run in
that order. Detaching and reattaching a program creates a new sequence at the end.

A classifier must be attached before a flow can be tracked for its protocol. No dormant memberships exist. Detaching a
classifier drains in-flight invocations, removes only memberships governed by that attach type, and disarms inspection
only when no other classifier map still requires it.

The link retains the map even if the map FD is closed or the map is unpinned.

### Flow enrollment

`bpf_flow_map_track()` is a BTF-resolved function callable from `sock_ops`:

```c
/**
 * @brief Tracks the current flow in a flow map and activates the map's classifier for that flow.
 *
 * The helper derives the flow identifier and stable metadata from the supplied sock_ops context.
 *
 * @param[in] context Current sock_ops context identifying the flow to track.
 * @param[in] flow_map Flow map whose applicable classifier will inspect the flow.
 * @param[in] flags Direction-selection flags from ebpf_flow_map_track_flag_t.
 *
 * @retval 0 The flow was tracked, or an identical membership already existed.
 * @retval -ENOTSUP The requested direction-selection mode is not implemented.
 * @retval <0 The operation failed for another reason.
 */
long
bpf_flow_map_track(bpf_sock_ops_t* context, struct bpf_map* flow_map, uint64_t flags);
```

The helper derives the flow ID from the current `sock_ops` context. A program cannot track another flow.

Direction-selection flags are:

```c
/**
 * @brief Selects the payload directions to activate for one flow-map membership.
 */
typedef enum _ebpf_flow_map_track_flag
{
    EBPF_FLOW_MAP_TRACK_DEFAULT = 0, /**< Uses the default behavior, which activates both directions. */
    EBPF_FLOW_MAP_TRACK_INBOUND =
        EBPF_FLOW_DIRECTION_INBOUND, /**< Requests inbound-only classification. */
    EBPF_FLOW_MAP_TRACK_OUTBOUND =
        EBPF_FLOW_DIRECTION_OUTBOUND, /**< Requests outbound-only classification. */
    EBPF_FLOW_MAP_TRACK_BOTH = EBPF_FLOW_DIRECTION_BOTH, /**< Requests classification in both directions. */
    EBPF_FLOW_MAP_TRACK_DIRECTION_MASK =
        EBPF_FLOW_DIRECTION_BOTH, /**< Mask containing all direction-selection bits. */
} ebpf_flow_map_track_flag_t;
```

The helper normalizes `DEFAULT` to `BOTH`. The TCP phase accepts only that normalized `BOTH` value; `INBOUND` and
`OUTBOUND` return `-ENOTSUP`. Programs still receive the current direction in the classification context and can
self-filter. The direction-selection phase enables single-direction invocation suppression.

A repeated track operation with the same normalized flags is idempotent. Any different flags for an existing flow/map
membership fail explicitly. Membership configuration is immutable for its lifetime.

Tracking fails if:

- the map has no classifier for the flow's protocol;
- the map is full;
- the flags contain unsupported or reserved bits; or
- the arguments or program type are invalid.

### Classification context

Stream and datagram programs share one context:

```c
/**
 * @brief Identifies the lifecycle event represented by a flow-classify invocation.
 */
typedef enum _ebpf_flow_classify_event
{
    EBPF_FLOW_CLASSIFY_EVENT_DATA,    /**< Payload is available for classification. */
    EBPF_FLOW_CLASSIFY_EVENT_DELETED, /**< The classifier membership is being cleaned up. */
} ebpf_flow_classify_event_t;

/**
 * @brief Contains stable flow metadata and the payload for one flow-classify invocation.
 *
 * Metadata fields are read-only. Payload pointers are valid only for the duration of the current invocation and can be
 * invalidated by bpf_flow_classify_pull_data().
 */
typedef struct _ebpf_flow_classify
{
    uint64_t flow_id; /**< Stable WFP flow identifier. */
    uint32_t family;  /**< IP address family. */
    union
    {
        uint32_t local_ip4;    /**< Local IPv4 address in network byte order. */
        uint32_t local_ip6[4]; /**< Local IPv6 address in network byte order. */
    };
    union
    {
        uint32_t remote_ip4;    /**< Remote IPv4 address in network byte order. */
        uint32_t remote_ip6[4]; /**< Remote IPv6 address in network byte order. */
    };
    uint32_t protocol;       /**< IP protocol number. */
    uint32_t compartment_id; /**< Network compartment identifier. */
    uint64_t interface_luid; /**< Local interface LUID. */
    uint64_t process_id;     /**< Initiating process identifier, if valid. */
    uint64_t logon_id;       /**< Initiating logon identifier, if valid. */
    int32_t is_admin;        /**< 1 for an administrator, 0 otherwise, or -1 when unavailable. */

    uint32_t event;            /**< One ebpf_flow_classify_event_t value. */
    uint32_t data_path;        /**< One ebpf_flow_classify_data_path_t value. */
    uint32_t metadata_flags;   /**< Bitmask of ebpf_flow_classify_metadata_flag_t values. */
    uint32_t direction;        /**< One ebpf_flow_direction_t value for the current payload. */
    uint32_t armed_directions; /**< Directions selected for this classifier membership. */

    union
    {
        struct
        {
            uint16_t local_port;  /**< Local TCP or UDP port in network byte order. */
            uint16_t remote_port; /**< Remote TCP or UDP port in network byte order. */
        } ports;                   /**< Port metadata when EBPF_FLOW_CLASSIFY_METADATA_PORTS_VALID is set. */
        struct
        {
            uint8_t type; /**< ICMP or ICMPv6 message type. */
            uint8_t code; /**< ICMP or ICMPv6 message code. */
        } icmp;           /**< ICMP metadata when EBPF_FLOW_CLASSIFY_METADATA_ICMP_TYPE_CODE_VALID is set. */
    } transport; /**< Protocol-specific transport metadata. */

    uint32_t data_length; /**< Total logical payload length for this invocation. */
    uint32_t missed_bytes; /**< Stream bytes not observed by this callout before the current payload. */
    uint8_t* data_start;   /**< Start of the directly accessible payload span. */
    uint8_t* data_end;     /**< End of the directly accessible payload span. */
} ebpf_flow_classify_t;
```

The concrete layout is non-final. Its contract is:

- `event` distinguishes payload delivery from final cleanup.
- `data_path` and `protocol` identify stream, UDP, ICMP, or ICMPv6.
- `metadata_flags` identifies valid transport and identity fields.
- `direction` is the current payload direction.
- `armed_directions` reports the membership's requested directions. It is `BOTH` during the TCP phase.
- `data_length` is the total logical payload length for this invocation.
- `data_start..data_end` is the directly accessible first span and is valid only for this invocation.
- `missed_bytes` reports stream bytes that WFP indicates this callout did not observe. Each classifier chooses whether
  to reset, fail closed, or continue.
- deletion has no payload; payload pointers are null and lengths are zero.

Process identity is captured when the flow is tracked, while ALE flow-establishment identity is valid. The extension
stores a fixed summary: `process_id`, `logon_id`, tri-state `is_admin`, and validity flags. It does not retain a raw
token or borrowed WFP identity pointer.

`bpf_get_current_logon_id(context)` and `bpf_is_current_admin(context)` are available to flow-classify programs and
return the captured values for source compatibility with `sock_addr`.

### Payload access

The context exposes payload length without requiring the payload to be contiguous. A classifier that needs more than
the directly accessible span calls:

```c
/**
 * @brief Makes a requested prefix of the current payload directly accessible to the program.
 *
 * A successful call can relocate payload storage and invalidates all payload-derived pointers previously checked by
 * the verifier.
 *
 * @param[in,out] context Current flow-classify context. The helper can update data_start and data_end.
 * @param[in] length Number of bytes to make directly accessible, or 0 to request the whole payload.
 *
 * @retval 0 The requested payload prefix is directly accessible.
 * @retval <0 The request is invalid or the payload could not be made directly accessible.
 */
long
bpf_flow_classify_pull_data(ebpf_flow_classify_t* context, uint32_t length);
```

- `length` requests that many bytes from the start of the current logical payload.
- `length == 0` requests the whole payload.
- a length larger than `data_length` fails;
- copying or linearization occurs only when needed;
- success can relocate payload storage and invalidates prior payload-derived pointers; and
- the program must reload `data_start` and `data_end` and repeat bounds checks.

This helper affects only the current invocation. It is independent of `NEED_MORE_DATA`, which permits the current
payload and asks to observe future payload.

### Actions and classifier composition

The synchronous action set is:

```c
/**
 * @brief Specifies a synchronous whole-flow classification action.
 */
typedef enum _ebpf_flow_classify_action
{
    EBPF_FLOW_CLASSIFY_ALLOW, /**< Finalizes the returning classifier and allows the current payload. */
    EBPF_FLOW_CLASSIFY_BLOCK, /**< Blocks the flow and terminates classification for every classifier. */
    EBPF_FLOW_CLASSIFY_NEED_MORE_DATA, /**< Allows the current payload and keeps the classifier active. */
} ebpf_flow_classify_action_t;
```

For each payload, the extension snapshots applicable active classifier links and invokes them in global attachment
order.

- **ALLOW**
  - permits the current payload unless another classifier blocks it;
  - finalizes only the returning classifier;
  - removes its membership after the current invocation; and
  - gives it no future data or deletion callback.
- **NEED_MORE_DATA**
  - permits the current payload unless another classifier blocks it;
  - keeps only the returning classifier active for future payload; and
  - does not hold, accumulate, replay, or partially permit the current payload.
- **BLOCK**
  - stops the classifier chain immediately;
  - blocks or absorbs the current payload;
  - is terminal for the entire flow;
  - requires the blocking classifier to clean its own program-owned flow state before returning;
  - gives every other still-active classifier one final `DELETED` cleanup invocation in attachment order; and
  - removes all memberships after cleanup so classifiers are not notified again on natural flow deletion.

Direction controls whether a classifier is invoked, not the scope of its verdict. A classifier armed only for ingress
can still block the whole flow.

When no active classifier remains, payload inspection is disarmed.

## Lifecycle

### Enrollment

At ALE flow establishment, the extension creates internal flow state containing the WFP flow ID, endpoint metadata,
protocol, process/security summary, and active classifier memberships. The `sock_ops` program can track the flow in one
or more flow maps.

TCP flows require the map's stream classifier. UDP and non-error ICMP/ICMPv6 flows require its datagram classifier.

### Payload delivery

For each payload indication:

1. Identify active memberships for the flow and current direction.
2. Snapshot applicable classifier links in global attachment order under rundown protection.
3. Invoke each classifier until the snapshot ends or one returns `BLOCK`.
4. Apply `ALLOW` or `NEED_MORE_DATA` to the returning classifier.
5. Permit the payload if no classifier blocked it.
6. Remove finalized memberships and disarm inspection when none remain.

### Flow deletion

WFP `flowDeleteFn` is the authoritative natural teardown signal. Every still-active classifier receives one
`DELETED` event in attachment order, with no payload and ignored return. The extension then removes memberships and
releases captured identity and WFP state.

Classifiers already finalized by `ALLOW` receive no cleanup callback. Classifiers already cleaned up after `BLOCK`
have no membership and are not called again.

### Link or map deletion

Deleting a classifier link prevents new invocation, drains in-flight invocation, and gives that classifier equivalent
membership cleanup before removing its entries. It does not fabricate a flow-wide deletion for classifiers in other
maps.

Deleting a flow map detaches its links and removes its memberships. Closing its FD or removing a pin has no effect
while links retain references.

## Stream and datagram behavior

### TCP stream

- An invocation represents an ordered stream-byte range in one direction.
- Callback boundaries are not TCP packet, TCP segment, or application-message boundaries.
- Every active classifier receives the same logical range.
- `data_length` is the total range length; direct access may expose only its first contiguous span.
- `missed_bytes` makes stream discontinuity explicit.
- `NEED_MORE_DATA` does not use WFP's accumulate-more-data action.

### UDP and ICMP/ICMPv6

Datagram classification covers UDP and non-error ICMP/ICMPv6. Raw IP datagrams and WFP's separate ICMP error layers
are out of scope.

- one invocation receives one logical UDP datagram or ICMP/ICMPv6 message;
- inbound and outbound offsets are normalized to one direction-independent payload contract;
- UDP payload begins after the UDP header;
- proposed ICMP payload begins after the base ICMP/ICMPv6 header, with type and code in metadata;
- IP fragment reassembly is not performed by the eBPF program; and
- the datagram callout does not advertise `ALLOW_USO` or `ALLOW_URO`, preserving logical datagram boundaries.

**Open question:** Whether ICMP payload should instead begin at the base ICMP/ICMPv6 header.

USO/URO normalization is outside this design. Its performance impact should be measured during datagram implementation.

## WFP integration

The eBPF contract maps to:

- `ALE_FLOW_ESTABLISHED_V4/V6` for `sock_ops` enrollment and identity capture;
- `STREAM_V4/V6` for TCP byte ranges; and
- `DATAGRAM_DATA_V4/V6` for UDP and non-error ICMP/ICMPv6.

The stream path uses one stream callout per address family. The datagram path uses one datagram callout per address
family. Flow context is associated with the applicable data-layer callout, and
`FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW` prevents invocation for flows with no associated context.

The TCP phase delivers both directions to tracked stream classifiers. Programs can inspect `direction` and self-filter.
The direction-selection phase persists and enforces the direction flags so classifiers are not invoked for unarmed
directions. Direction-specific WFP callouts are outside this design.

Stream and datagram payload can be scatter/gather. The extension derives total logical length and the first contiguous
span without unconditionally flattening data. `bpf_flow_classify_pull_data()` copies only the requested range.

`BLOCK` maps to blocking/absorbing the current payload and terminating the current WFP flow where applicable. The design
does not promise a particular on-wire TCP signal. Connectionless traffic can later create a new WFP flow and be
evaluated again.

## Pending flows

`EBPF_FLOW_CLASSIFY_PEND` means withhold the current logical payload for an external decision. It is not equivalent to
`NEED_MORE_DATA`. Pending is implemented in a separate phase.

The pending design uses:

- append `PEND` to the program action enum;
- add a flow-classify-specific pend helper;
- add a dedicated completion map and a kernel-private pend table;
- publish pending events through an extension-owned subscription associated with the completion map;
- allow optional bounded program data and a requested bounded payload prefix in the event;
- allow at most one outstanding pend per flow;
- freeze the classifier chain at the first pending classifier;
- retain later payload in both directions behind the pend; and
- initially complete with `ALLOW`, `BLOCK`, or `NEED_MORE_DATA`.

`ALLOW` finalizes the pending classifier and resumes later classifiers on the held payload. `NEED_MORE_DATA` permits the
held payload for that classifier, keeps it active for future payload, and resumes later classifiers. `BLOCK` discards
all held data and terminates the flow. `REINVOKE` is outside the initial pending phase.

Pending requires bounded retained bytes, exactly-once completion, stale/duplicate rejection, client isolation, timeout,
flow-deletion cancellation, and stream/datagram reinjection. Quota exhaustion fails closed with `BLOCK`. Timeout is
proposed to use a secure system default and maximum with optional shorter subscription configuration.

Exact pending structures, queue algorithms, timeout values, teardown behavior, and reinjection mechanics are outside
this document.

## Security and resource management

- Only the current `sock_ops` context can authorize tracking its flow.
- The fixed map key is the context-derived WFP flow ID.
- Flow metadata and identity are extension-owned and read-only.
- Flow-map handles provide observation authority only; standard update and delete are rejected.
- eBPF programs cannot use standard map CRUD on flow maps.
- Classifier links retain their maps and scope membership ownership.
- Token-derived identity is copied or derived at enrollment; no raw token pointer is exposed or retained.
- Map capacity and allocation failures are returned explicitly.
- Pending payload and identity are disclosed only to the owning completion-map subscriber.

## Verifier, ABI, and versioning

- New helpers use BTF-resolved functions.
- `ebpf_flow_classify_t` is a fixed, verifier-described, read-only metadata and payload context.
- The context and flow-map value use one layout for stream and datagram classification.
- The TCP phase registers the stream attach type. The datagram phase registers the datagram attach type.
- Metadata validity uses append-only bit flags with reserved bits.
- Unsupported single-direction modes fail explicitly until the direction-selection phase.
- The synchronous action enum contains only implemented actions. `PEND` is added with the pending phase.
- Pending notification and completion structures are independently versioned.
- The flow-map entry contains no pending control fields, retained payload, or writable program state.
- Native-code and product version gates are updated whenever context or helper ABI changes.

## Validation

### Local

- custom-map creation, lookup/enumeration, rejected mutation, and program-type association;
- map-target program attach, map/link lifetime, and one-program-per-attach-type enforcement;
- enrollment helper validation, idempotency, capacity, and unsupported direction flags;
- verifier and program-information acceptance of the context and actions;
- verifier invalidation of payload pointers after `bpf_flow_classify_pull_data()`; and
- action aggregation and cleanup state-machine tests.

### VM / live network stack

- TCP enrollment, ordered stream delivery, discontinuity, lazy payload access, allow, block, and need-more-data;
- multiple classifier maps and deterministic attachment order;
- flow, link, and map deletion cleanup;
- process/logon/admin identity validity and stability;
- direction reporting and program-side filtering;
- stress with many flows, high data rates, attach/detach churn, and map capacity.

The datagram phase adds UDP and ICMP/ICMPv6 boundary, metadata, cleanup, action, offload, and performance tests. The
pending phase adds retention, reinjection, queueing, timeout, quota, completion-race, and cancellation tests.

## Implementation phases

### Phase 1A: common interface and core plumbing

- register the flow-classify program type, stream attach type, and flow-map type;
- add map-target link attachment with resolved map lifetime;
- add BTF-resolved enrollment and payload-access functions;
- define the shared stream/datagram context and map-value layouts; and
- add user-mode/libbpf attach support.

### Phase 1B: TCP stream implementation

- capture identity and create internal per-flow state at ALE flow establishment;
- implement flow-map tracking with bidirectional arming only;
- register conditional stream callouts;
- implement stream payload access, classifier ordering, actions, and cleanup; and
- validate and harden the TCP path.

### Phase 1C: direction selection

- enable the ingress-only and egress-only flag values already defined in Phase 1A;
- persist per-membership direction masks; and
- suppress eBPF invocation for unarmed directions.

### Phase 1D: datagram implementation

- register and publish the datagram attach type and section;
- implement UDP and non-error ICMP/ICMPv6 normalization and callouts;
- finalize the ICMP payload boundary;
- disable USO/URO for the initial datagram implementation; and
- validate correctness and measure performance.

### Phase 2: asynchronous pending

- finalize the pending-specific APIs and remaining operational decisions;
- add `PEND`, the pend helper, completion map, subscription, and internal pend table;
- retain and reinject stream/datagram payload;
- enforce queue, quota, timeout, and cancellation rules; and
- add fault, race, stress, and restart testing.
