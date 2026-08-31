// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// This program provides map-in-map coverage for every supported inner map type
// against both outer map types (BPF_MAP_TYPE_ARRAY_OF_MAPS and
// BPF_MAP_TYPE_HASH_OF_MAPS). Each (outer, inner) pair gets its own inner map
// template so that a lookup returning the wrong inner map is detectable.
//
// Each pair is exercised in one of two directions, chosen by what the inner map
// type supports from within an eBPF program:
//
//   Test seeds, program reads:  HASH, ARRAY, LRU_HASH, LPM_TRIE
//   Program writes, test reads: PERCPU_HASH, PERCPU_ARRAY, LRU_PERCPU_HASH,
//                               QUEUE, STACK, RINGBUF, PERF_EVENT_ARRAY
//
// Both directions prove that the outer map lookup resolved to the correct inner
// map, because the value carried across is unique per pair.
//
// The per-pair outcome is written to the "results" map at the pair's index. On
// success every pair records its own unique sentinel, so the test applies one
// uniform assertion: results[i] == MIM_SENTINEL(i). Failures record a negative
// MIM_STATUS_* value or the failing helper's error code. Index assignment is:
//     0..10  -> BPF_MAP_TYPE_ARRAY_OF_MAPS pairs
//     11..21 -> BPF_MAP_TYPE_HASH_OF_MAPS pairs
// The offsets within each block are declared by MIM_INNER_MAP_TYPES in
// map_in_map_all_types.h so that the test and this program cannot disagree.

#include "bpf_helpers.h"
#include "map_in_map_all_types.h"
#include "sample_ext_helpers.h"

// Inner map key used for the LPM_TRIE pairs.
typedef struct _mim_lpm_key
{
    uint32_t prefix_length;
    uint32_t value;
} mim_lpm_key_t;

// Declares an inner map template plus an outer map statically initialized to
// reference it. Used for inner map types that take a uint32_t key and value.
#define MIM_PAIR_KV(NAME, INNER_TYPE, OUTER_TYPE)   \
    struct                                          \
    {                                               \
        __uint(type, INNER_TYPE);                   \
        __type(key, uint32_t);                      \
        __type(value, uint32_t);                    \
        __uint(max_entries, MIM_INNER_MAX_ENTRIES); \
    } inner_##NAME SEC(".maps");                    \
                                                    \
    struct                                          \
    {                                               \
        __uint(type, OUTER_TYPE);                   \
        __type(key, uint32_t);                      \
        __type(value, uint32_t);                    \
        __uint(max_entries, 1);                     \
        __array(values, inner_##NAME);              \
    } outer_##NAME SEC(".maps") = {.values = {&inner_##NAME}};

// As MIM_PAIR_KV, but for LPM_TRIE inner maps, which require a prefix-length
// prefixed key.
#define MIM_PAIR_LPM(NAME, INNER_TYPE, OUTER_TYPE)  \
    struct                                          \
    {                                               \
        __uint(type, INNER_TYPE);                   \
        __type(key, mim_lpm_key_t);                 \
        __type(value, uint32_t);                    \
        __uint(max_entries, MIM_INNER_MAX_ENTRIES); \
    } inner_##NAME SEC(".maps");                    \
                                                    \
    struct                                          \
    {                                               \
        __uint(type, OUTER_TYPE);                   \
        __type(key, uint32_t);                      \
        __type(value, uint32_t);                    \
        __uint(max_entries, 1);                     \
        __array(values, inner_##NAME);              \
    } outer_##NAME SEC(".maps") = {.values = {&inner_##NAME}};

// As MIM_PAIR_KV, but for QUEUE and STACK inner maps, which have no key.
#define MIM_PAIR_NO_KEY(NAME, INNER_TYPE, OUTER_TYPE) \
    struct                                            \
    {                                                 \
        __uint(type, INNER_TYPE);                     \
        __uint(value_size, sizeof(uint32_t));         \
        __uint(max_entries, MIM_INNER_MAX_ENTRIES);   \
    } inner_##NAME SEC(".maps");                      \
                                                      \
    struct                                            \
    {                                                 \
        __uint(type, OUTER_TYPE);                     \
        __type(key, uint32_t);                        \
        __type(value, uint32_t);                      \
        __uint(max_entries, 1);                       \
        __array(values, inner_##NAME);                \
    } outer_##NAME SEC(".maps") = {.values = {&inner_##NAME}};

// As MIM_PAIR_KV, but for RINGBUF and PERF_EVENT_ARRAY inner maps, which have
// neither a key nor a fixed value size.
#define MIM_PAIR_EVENT(NAME, INNER_TYPE, OUTER_TYPE) \
    struct                                           \
    {                                                \
        __uint(type, INNER_TYPE);                    \
        __uint(max_entries, MIM_EVENT_MAP_SIZE);     \
    } inner_##NAME SEC(".maps");                     \
                                                     \
    struct                                           \
    {                                                \
        __uint(type, OUTER_TYPE);                    \
        __type(key, uint32_t);                       \
        __type(value, uint32_t);                     \
        __uint(max_entries, 1);                      \
        __array(values, inner_##NAME);               \
    } outer_##NAME SEC(".maps") = {.values = {&inner_##NAME}};

// Declares the inner map template and outer map for every row of
// MIM_INNER_MAP_TYPES, for one outer map type. The row macro is redefined for
// each outer map type because the table supplies only its own columns.
#define MIM_DECLARE_ROW(INDEX, NAME, TAG, SHAPE, TYPE, OP) \
    MIM_PAIR_##SHAPE(NAME##_aom, TYPE, BPF_MAP_TYPE_ARRAY_OF_MAPS)
MIM_INNER_MAP_TYPES(MIM_DECLARE_ROW)
#undef MIM_DECLARE_ROW

#define MIM_DECLARE_ROW(INDEX, NAME, TAG, SHAPE, TYPE, OP) MIM_PAIR_##SHAPE(NAME##_hom, TYPE, BPF_MAP_TYPE_HASH_OF_MAPS)
MIM_INNER_MAP_TYPES(MIM_DECLARE_ROW)
#undef MIM_DECLARE_ROW

// Per-pair outcome, indexed by MIM_BASE_* plus the pair's INDEX column. Values
// are the pair's sentinel on success, or a negative MIM_STATUS_* / helper error
// on failure.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, int32_t);
    __uint(max_entries, MIM_RESULT_COUNT);
} results SEC(".maps");

static inline void
_mim_store_result(uint32_t index, int32_t status)
{
    bpf_map_update_elem(&results, &index, &status, BPF_ANY);
}

// Looks up the inner map, reads the value the test seeded at key 0, and records
// it. The test asserts the recorded value equals the pair's sentinel.
#define MIM_OP_READ(INDEX, NAME)                                                 \
    {                                                                            \
        int32_t status = MIM_STATUS_NO_INNER_MAP;                                \
        void* inner = bpf_map_lookup_elem(&outer_##NAME, &outer_key);            \
        if (inner) {                                                             \
            uint32_t inner_key = 0;                                              \
            uint32_t* found = (uint32_t*)bpf_map_lookup_elem(inner, &inner_key); \
            status = found ? (int32_t) * found : MIM_STATUS_NO_INNER_VALUE;      \
        }                                                                        \
        _mim_store_result(INDEX, status);                                        \
    }

// As MIM_OP_READ, but builds the prefix-length prefixed key an LPM_TRIE needs.
#define MIM_OP_READ_LPM(INDEX, NAME)                                              \
    {                                                                             \
        int32_t status = MIM_STATUS_NO_INNER_MAP;                                 \
        void* inner = bpf_map_lookup_elem(&outer_##NAME, &outer_key);             \
        if (inner) {                                                              \
            mim_lpm_key_t inner_key = {MIM_LPM_PREFIX_LENGTH, MIM_LPM_KEY_VALUE}; \
            uint32_t* found = (uint32_t*)bpf_map_lookup_elem(inner, &inner_key);  \
            status = found ? (int32_t) * found : MIM_STATUS_NO_INNER_VALUE;       \
        }                                                                         \
        _mim_store_result(INDEX, status);                                         \
    }

// Looks up the inner map and writes the pair's sentinel into it. The test reads
// the sentinel back from that specific inner map. Used for the per-CPU types:
// the write lands only in the current CPU's slot, so the test asserts exactly
// one slot holds the sentinel and the rest are zero.
#define MIM_OP_WRITE(INDEX, NAME)                                                    \
    {                                                                                \
        int32_t status = MIM_STATUS_NO_INNER_MAP;                                    \
        void* inner = bpf_map_lookup_elem(&outer_##NAME, &outer_key);                \
        if (inner) {                                                                 \
            uint32_t inner_key = 0;                                                  \
            uint32_t value = MIM_SENTINEL(INDEX);                                    \
            int64_t error = bpf_map_update_elem(inner, &inner_key, &value, BPF_ANY); \
            status = (error == 0) ? (int32_t)MIM_SENTINEL(INDEX) : (int32_t)error;   \
        }                                                                            \
        _mim_store_result(INDEX, status);                                            \
    }

// Looks up the inner map and pushes the pair's sentinel. The test pops it back
// off that specific inner map.
#define MIM_OP_PUSH(INDEX, NAME)                                                   \
    {                                                                              \
        int32_t status = MIM_STATUS_NO_INNER_MAP;                                  \
        void* inner = bpf_map_lookup_elem(&outer_##NAME, &outer_key);              \
        if (inner) {                                                               \
            uint32_t value = MIM_SENTINEL(INDEX);                                  \
            int64_t error = bpf_map_push_elem(inner, &value, 0);                   \
            status = (error == 0) ? (int32_t)MIM_SENTINEL(INDEX) : (int32_t)error; \
        }                                                                          \
        _mim_store_result(INDEX, status);                                          \
    }

// Looks up the inner ring buffer and writes the pair's sentinel. The test
// consumes it from that specific inner map.
#define MIM_OP_RINGBUF(INDEX, NAME)                                                \
    {                                                                              \
        int32_t status = MIM_STATUS_NO_INNER_MAP;                                  \
        void* inner = bpf_map_lookup_elem(&outer_##NAME, &outer_key);              \
        if (inner) {                                                               \
            uint32_t value = MIM_SENTINEL(INDEX);                                  \
            int error = bpf_ringbuf_output(inner, &value, sizeof(value), 0);       \
            status = (error == 0) ? (int32_t)MIM_SENTINEL(INDEX) : (int32_t)error; \
        }                                                                          \
        _mim_store_result(INDEX, status);                                          \
    }

// Looks up the inner perf event array and writes the pair's sentinel. The test
// consumes it from that specific inner map.
#define MIM_OP_PERF(INDEX, NAME)                                                         \
    {                                                                                    \
        int32_t status = MIM_STATUS_NO_INNER_MAP;                                        \
        void* inner = bpf_map_lookup_elem(&outer_##NAME, &outer_key);                    \
        if (inner) {                                                                     \
            uint32_t value = MIM_SENTINEL(INDEX);                                        \
            uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU;                                  \
            int error = bpf_perf_event_output(ctx, inner, flags, &value, sizeof(value)); \
            status = (error == 0) ? (int32_t)MIM_SENTINEL(INDEX) : (int32_t)error;       \
        }                                                                                \
        _mim_store_result(INDEX, status);                                                \
    }

// Exercises every row of MIM_INNER_MAP_TYPES for one outer map type. The row
// macro is redefined per outer map type, as for MIM_DECLARE_ROW above.
SEC("sample_ext") int array_of_maps_all_types(sample_program_context_t* ctx)
{
    uint32_t outer_key = MIM_OUTER_KEY;
#define MIM_RUN_ROW(INDEX, NAME, TAG, SHAPE, TYPE, OP) MIM_OP_##OP(MIM_BASE_ARRAY_OF_MAPS + (INDEX), NAME##_aom)
    MIM_INNER_MAP_TYPES(MIM_RUN_ROW)
#undef MIM_RUN_ROW
    return 0;
}

SEC("sample_ext") int hash_of_maps_all_types(sample_program_context_t* ctx)
{
    uint32_t outer_key = MIM_OUTER_KEY;
#define MIM_RUN_ROW(INDEX, NAME, TAG, SHAPE, TYPE, OP) MIM_OP_##OP(MIM_BASE_HASH_OF_MAPS + (INDEX), NAME##_hom)
    MIM_INNER_MAP_TYPES(MIM_RUN_ROW)
#undef MIM_RUN_ROW
    return 0;
}
