// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Test-side description of the (outer, inner) map pairs declared by the
 * map_in_map_all_types.c eBPF program.
 *
 * The set of inner map types is generated from the same ALL_INNER_MAP_TYPES /
 * MAP_OF_MAPS_TYPES macro lists that the Catch2 TEMPLATE_TEST_CASEs use, so this
 * table cannot drift away from the set of map types under test. The sentinels
 * and the shared map parameters come from map_in_map_all_types.h, which the eBPF
 * program also includes, so the test and the program cannot disagree about them.
 *
 * What each inner map type should look like once the loader has created it is
 * stated here independently of how the eBPF program declares it. That
 * independence is what makes the static initializer test meaningful: it compares
 * what the loader produced against an expectation that was not derived from the
 * declaration being checked. Do not collapse this table into the
 * MIM_INNER_MAP_TYPES table in map_in_map_all_types.h.
 */

#include "common_tests.h"
#include "map_in_map_all_types.h"

#include <string>
#include <string_view>
#include <vector>

/**
 * @brief Direction in which the sentinel value travels between the test and the
 * eBPF program, determined by what a given inner map type supports from within
 * an eBPF program.
 */
enum class map_in_map_direction
{
    test_seeds_program_reads, ///< Test writes the sentinel, program reads it back.
    test_seeds_lpm_trie,      ///< As above, but the key is a prefix-length prefixed LPM key.
    program_writes_per_cpu,   ///< Program writes; test scans every per-CPU slot.
    program_pushes,           ///< Program pushes; test pops from the inner map.
    program_writes_ringbuf,   ///< Program writes; test consumes the inner ring buffer.
    program_writes_perf,      ///< Program writes; test consumes the inner perf event array.
};

/**
 * @brief Everything the test needs to exercise and verify one (outer, inner) pair.
 */
typedef struct _map_in_map_pair
{
    bpf_map_type inner_map_type;
    bpf_map_type outer_map_type;
    std::string inner_map_name;     ///< Name of the inner map template in the ELF file.
    std::string outer_map_name;     ///< Name of the outer map in the ELF file.
    uint32_t results_index;         ///< Index into the program's "results" map.
    int32_t sentinel;               ///< Unique value carried between test and program.
    map_in_map_direction direction; ///< How the sentinel travels.
    uint32_t expected_key_size;     ///< Expected inner map key size.
    uint32_t expected_value_size;   ///< Expected inner map value size (per-CPU element size).
    uint32_t expected_max_entries;  ///< Expected inner map max_entries.
} map_in_map_pair_t;

/**
 * @brief Per-inner-map-type constants. Specialized for every type named in
 * ALL_INNER_MAP_TYPES; a missing specialization is a compile error, which is how
 * this table is kept in sync with that macro.
 */
template <typename inner_map_tag_t> struct map_in_map_inner_traits;

/**
 * @brief Expected shape of an inner map once the loader has created it.
 *
 * Stated here independently of the MIM_PAIR_* macros in map_in_map_all_types.c
 * on purpose: these are the expectation half of the static initializer test, so
 * deriving them from the program's own declarations would make those assertions
 * compare the program to itself.
 */
#define MIM_EXPECT_KEY_SIZE_KV sizeof(uint32_t)
#define MIM_EXPECT_KEY_SIZE_LPM (2 * sizeof(uint32_t))
#define MIM_EXPECT_KEY_SIZE_NO_KEY 0
#define MIM_EXPECT_KEY_SIZE_EVENT 0
#define MIM_EXPECT_VALUE_SIZE_KV sizeof(uint32_t)
#define MIM_EXPECT_VALUE_SIZE_LPM sizeof(uint32_t)
#define MIM_EXPECT_VALUE_SIZE_NO_KEY sizeof(uint32_t)
#define MIM_EXPECT_VALUE_SIZE_EVENT 0
#define MIM_EXPECT_MAX_ENTRIES_KV MIM_INNER_MAX_ENTRIES
#define MIM_EXPECT_MAX_ENTRIES_LPM MIM_INNER_MAX_ENTRIES
#define MIM_EXPECT_MAX_ENTRIES_NO_KEY MIM_INNER_MAX_ENTRIES
#define MIM_EXPECT_MAX_ENTRIES_EVENT MIM_EVENT_MAP_SIZE

// clang-format off
#define DECLARE_MAP_IN_MAP_INNER_TRAITS(TAG, SHORT_NAME, OFFSET, SHAPE, DIRECTION)                                     \
    template <> struct map_in_map_inner_traits<TAG>                                                                    \
    {                                                                                                                  \
        static constexpr const char* short_name = SHORT_NAME;                                                          \
        static constexpr uint32_t offset = (OFFSET);                                                                   \
        static constexpr map_in_map_direction direction = map_in_map_direction::DIRECTION;                             \
        static constexpr uint32_t key_size = MIM_EXPECT_KEY_SIZE_##SHAPE;                                              \
        static constexpr uint32_t value_size = MIM_EXPECT_VALUE_SIZE_##SHAPE;                                          \
        static constexpr uint32_t max_entries = MIM_EXPECT_MAX_ENTRIES_##SHAPE;                                        \
    };

// Shape and direction are restated independently from the eBPF table because
// they form the test oracle. Identity fields are cross-checked below.
//                              tag                     short name      off shape   direction
DECLARE_MAP_IN_MAP_INNER_TRAITS(hash_map_t,             "hash",         0,  KV,     test_seeds_program_reads)
DECLARE_MAP_IN_MAP_INNER_TRAITS(array_map_t,            "array",        1,  KV,     test_seeds_program_reads)
DECLARE_MAP_IN_MAP_INNER_TRAITS(lru_hash_map_t,         "lru_hash",     2,  KV,     test_seeds_program_reads)
DECLARE_MAP_IN_MAP_INNER_TRAITS(lpm_trie_map_t,         "lpm_trie",     3,  LPM,    test_seeds_lpm_trie)
DECLARE_MAP_IN_MAP_INNER_TRAITS(percpu_hash_map_t,      "percpu_hash",  4,  KV,     program_writes_per_cpu)
DECLARE_MAP_IN_MAP_INNER_TRAITS(percpu_array_map_t,     "percpu_array", 5,  KV,     program_writes_per_cpu)
DECLARE_MAP_IN_MAP_INNER_TRAITS(lru_percpu_hash_map_t,  "lru_percpu",   6,  KV,     program_writes_per_cpu)
DECLARE_MAP_IN_MAP_INNER_TRAITS(queue_map_t,            "queue",        7,  NO_KEY, program_pushes)
DECLARE_MAP_IN_MAP_INNER_TRAITS(stack_map_t,            "stack",        8,  NO_KEY, program_pushes)
DECLARE_MAP_IN_MAP_INNER_TRAITS(ringbuf_map_t,          "ringbuf",      9,  EVENT,  program_writes_ringbuf)
DECLARE_MAP_IN_MAP_INNER_TRAITS(perf_event_array_map_t, "perf",         10, EVENT,  program_writes_perf)
// clang-format on

#undef DECLARE_MAP_IN_MAP_INNER_TRAITS
#undef MIM_EXPECT_KEY_SIZE_KV
#undef MIM_EXPECT_KEY_SIZE_LPM
#undef MIM_EXPECT_KEY_SIZE_NO_KEY
#undef MIM_EXPECT_KEY_SIZE_EVENT
#undef MIM_EXPECT_VALUE_SIZE_KV
#undef MIM_EXPECT_VALUE_SIZE_LPM
#undef MIM_EXPECT_VALUE_SIZE_NO_KEY
#undef MIM_EXPECT_VALUE_SIZE_EVENT
#undef MIM_EXPECT_MAX_ENTRIES_KV
#undef MIM_EXPECT_MAX_ENTRIES_LPM
#undef MIM_EXPECT_MAX_ENTRIES_NO_KEY
#undef MIM_EXPECT_MAX_ENTRIES_EVENT

// The number of inner map types must agree between the eBPF program's table,
// the constant the program derives its results indices from, and the tag list
// the Catch2 TEMPLATE_TEST_CASEs use. Adding a type to one but not the others
// is a compile error here rather than silently reduced coverage.
#define MIM_COUNT_ROW(INDEX, NAME, TAG, SHAPE, TYPE, OP) +1
static_assert(
    (0 MIM_INNER_MAP_TYPES(MIM_COUNT_ROW)) == MIM_PAIRS_PER_OUTER,
    "MIM_INNER_MAP_TYPES and MIM_PAIRS_PER_OUTER disagree about the number of inner map types");
#undef MIM_COUNT_ROW

template <typename... inner_map_tags_t> inline constexpr size_t _mim_tag_count = sizeof...(inner_map_tags_t);

static_assert(
    _mim_tag_count<ALL_INNER_MAP_TYPES> == MIM_PAIRS_PER_OUTER,
    "ALL_INNER_MAP_TYPES and MIM_INNER_MAP_TYPES cover a different number of inner map types");

// Cross-check the identity columns while leaving SHAPE and OP independent.
#define MIM_VALIDATE_ROW(INDEX, NAME, TAG, SHAPE, TYPE, OP)                                             \
    static_assert(map_in_map_inner_traits<TAG>::offset == (INDEX), "Map-in-map result index mismatch"); \
    static_assert(TAG::value == (TYPE), "Map-in-map type tag mismatch");                                \
    static_assert(                                                                                      \
        std::string_view(map_in_map_inner_traits<TAG>::short_name) == #NAME, "Map-in-map short name mismatch");
MIM_INNER_MAP_TYPES(MIM_VALIDATE_ROW)
#undef MIM_VALIDATE_ROW

/**
 * @brief Build the descriptor for one inner map type paired with one outer map type.
 */
template <typename inner_map_tag_t>
static map_in_map_pair_t
_make_map_in_map_pair(bpf_map_type outer_map_type)
{
    typedef map_in_map_inner_traits<inner_map_tag_t> traits_t;

    const bool array_outer = (outer_map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS);
    const std::string suffix = array_outer ? "_aom" : "_hom";
    const uint32_t results_index = (array_outer ? MIM_BASE_ARRAY_OF_MAPS : MIM_BASE_HASH_OF_MAPS) + traits_t::offset;

    return map_in_map_pair_t{
        inner_map_tag_t::value,
        outer_map_type,
        "inner_" + std::string(traits_t::short_name) + suffix,
        "outer_" + std::string(traits_t::short_name) + suffix,
        results_index,
        static_cast<int32_t>(MIM_SENTINEL(results_index)),
        traits_t::direction,
        traits_t::key_size,
        traits_t::value_size,
        traits_t::max_entries};
}

/**
 * @brief Expand a list of inner map type tags into one descriptor per (outer, inner) pair.
 */
template <typename... inner_map_tags_t>
static std::vector<map_in_map_pair_t>
_make_map_in_map_pairs()
{
    std::vector<map_in_map_pair_t> pairs;
    (pairs.push_back(_make_map_in_map_pair<inner_map_tags_t>(BPF_MAP_TYPE_ARRAY_OF_MAPS)), ...);
    (pairs.push_back(_make_map_in_map_pair<inner_map_tags_t>(BPF_MAP_TYPE_HASH_OF_MAPS)), ...);
    return pairs;
}

/**
 * @brief All (outer, inner) pairs declared by map_in_map_all_types.c, derived from
 * ALL_INNER_MAP_TYPES so that adding an inner map type extends this table automatically.
 */
inline const std::vector<map_in_map_pair_t>&
map_in_map_pairs()
{
    static const std::vector<map_in_map_pair_t> pairs = _make_map_in_map_pairs<ALL_INNER_MAP_TYPES>();
    return pairs;
}

/**
 * @brief Name of the eBPF program that exercises the pairs for a given outer map type.
 */
inline const char*
map_in_map_program_name(bpf_map_type outer_map_type)
{
    return (outer_map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS) ? "array_of_maps_all_types" : "hash_of_maps_all_types";
}
