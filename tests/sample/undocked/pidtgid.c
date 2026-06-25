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

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct value
{
    uint32_t context_pid;
    uint32_t current_pid;
    uint32_t current_tid;
} value;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct value);
    __uint(max_entries, 1);
} pidtgid_map SEC(".maps");

SEC("sample_ext")
int
func(sample_program_context_t* ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    struct value value = {
        .context_pid = ctx->uint32_data, .current_pid = pid_tgid >> 32, .current_tid = pid_tgid & 0xFFFFFFFF};
    uint32_t key = 0;
    bpf_map_update_elem(&pidtgid_map, &key, &value, 0);

    return 0;
}
