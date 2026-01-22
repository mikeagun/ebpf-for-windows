// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    const int nonexistent_fd = 12345678;

    void
    ebpf_test_tail_call(_In_z_ const char* filename, uint32_t expected_result);

    void
    test_invalid_bpf_action(char log_buffer[]);

#ifdef __cplusplus
}
#endif