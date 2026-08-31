// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

// Shared contract between the map_in_map_all_types.c eBPF program and the tests
// that drive it. Keeping the indices, sentinels and map parameters in one place
// means the program and the test cannot disagree about what a given results
// entry represents.
//
// This header is included from an eBPF program compiled with clang -target bpf
// as well as from C++ test code, so it must contain only preprocessor
// definitions.

// Key used to look up the inner map in every outer map. Both outer map types
// are declared with max_entries == 1, so this is the only valid key.
#define MIM_OUTER_KEY 0

// max_entries for inner maps that hold key/value entries.
#define MIM_INNER_MAX_ENTRIES 10

// max_entries (byte capacity) for inner ring buffer and perf event array maps.
#define MIM_EVENT_MAP_SIZE 8192

// Key used for the LPM_TRIE inner maps. The trie key is a prefix length
// followed by the value being matched.
#define MIM_LPM_PREFIX_LENGTH 32
#define MIM_LPM_KEY_VALUE 0x0a000001

// The (outer, inner) pairs declared by map_in_map_all_types.c. This is the
// single source of truth for the eBPF side of the test: the inner and outer map
// declarations, the operation performed on each pair, and the pair's results
// index are all generated from it.
//
// tests\libs\common\map_in_map_tests.h restates, independently, what each inner
// map type should look like once it has been created. That restatement is the
// oracle the static initializer test compares the loader against, so the two
// tables must NOT be merged: deriving one from the other would make those
// assertions compare the program to itself.
//
// Columns:
//   INDEX  Offset of the pair within one outer map type's block of results.
//          Row order is also the order the maps appear in the ELF file, which
//          the committed bpf2c expected output depends on, so do not reorder
//          rows without regenerating tests\bpf2c_tests\expected.
//   NAME   Builds the map names "inner_<NAME>_<aom|hom>" and
//          "outer_<NAME>_<aom|hom>".
//   TAG    C++ map type tag used to cross-check this row against the test-side
//          traits. It is ignored when this table is expanded by the C program.
//   SHAPE  Key/value shape of the inner map. Selects MIM_PAIR_<SHAPE>.
//   TYPE   The inner map's type.
//   OP     How the pair is exercised from the eBPF program. Selects
//          MIM_OP_<OP>.
// clang-format off
#define MIM_INNER_MAP_TYPES(X)                                                                               \
    X(0,  hash,         hash_map_t,             KV,     BPF_MAP_TYPE_HASH,             READ)                  \
    X(1,  array,        array_map_t,            KV,     BPF_MAP_TYPE_ARRAY,            READ)                  \
    X(2,  lru_hash,     lru_hash_map_t,         KV,     BPF_MAP_TYPE_LRU_HASH,         READ)                  \
    X(3,  lpm_trie,     lpm_trie_map_t,         LPM,    BPF_MAP_TYPE_LPM_TRIE,         READ_LPM)              \
    X(4,  percpu_hash,  percpu_hash_map_t,      KV,     BPF_MAP_TYPE_PERCPU_HASH,      WRITE)                 \
    X(5,  percpu_array, percpu_array_map_t,     KV,     BPF_MAP_TYPE_PERCPU_ARRAY,     WRITE)                 \
    X(6,  lru_percpu,   lru_percpu_hash_map_t,  KV,     BPF_MAP_TYPE_LRU_PERCPU_HASH,  WRITE)                 \
    X(7,  queue,        queue_map_t,            NO_KEY, BPF_MAP_TYPE_QUEUE,            PUSH)                  \
    X(8,  stack,        stack_map_t,            NO_KEY, BPF_MAP_TYPE_STACK,            PUSH)                  \
    X(9,  ringbuf,      ringbuf_map_t,          EVENT,  BPF_MAP_TYPE_RINGBUF,          RINGBUF)               \
    X(10, perf,         perf_event_array_map_t, EVENT,  BPF_MAP_TYPE_PERF_EVENT_ARRAY, PERF)
// clang-format on

// Number of inner map types exercised against each outer map type.
//
// Deliberately a literal rather than a count derived from MIM_INNER_MAP_TYPES:
// it is used from inside expansions of that same macro, and a macro cannot
// re-expand while its own expansion is still active, so a derived form would
// survive into the output as literal macro text. map_in_map_tests.h asserts at
// compile time that this matches the number of rows.
#define MIM_PAIRS_PER_OUTER 11

// First results index for each outer map type's block.
#define MIM_BASE_ARRAY_OF_MAPS 0
#define MIM_BASE_HASH_OF_MAPS MIM_PAIRS_PER_OUTER

// Total number of (outer, inner) pairs, and therefore the size of the results
// map.
#define MIM_RESULT_COUNT (2 * MIM_PAIRS_PER_OUTER)

// Value carried between the test and the program to prove that the outer map
// lookup resolved to the correct inner map. Unique per pair, never zero, and
// always positive when interpreted as int32_t so that it cannot be confused
// with a negative error status.
#define MIM_SENTINEL_BASE 0x5A5A0000
#define MIM_SENTINEL(index) (MIM_SENTINEL_BASE + (index))

// Status values reported when a pair could not be exercised. Both are negative
// so they can never collide with a sentinel.
#define MIM_STATUS_NO_INNER_MAP (-1)   ///< Lookup of the inner map failed.
#define MIM_STATUS_NO_INNER_VALUE (-2) ///< Inner map held no value at the key.
