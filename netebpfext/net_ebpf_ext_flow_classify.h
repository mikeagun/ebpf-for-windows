// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

// Callout GUIDs

// Flow established callouts for flow_classify hook
// a1b2c3d4-5e6f-7890-abcd-ef1234567890
DEFINE_GUID(
    EBPF_HOOK_FLOW_CLASSIFY_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
    0xa1b2c3d4,
    0x5e6f,
    0x7890,
    0xab,
    0xcd,
    0xef,
    0x12,
    0x34,
    0x56,
    0x78,
    0x90);

// a1b2c3d5-5e6f-7890-abcd-ef1234567890
DEFINE_GUID(
    EBPF_HOOK_FLOW_CLASSIFY_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
    0xa1b2c3d5,
    0x5e6f,
    0x7890,
    0xab,
    0xcd,
    0xef,
    0x12,
    0x34,
    0x56,
    0x78,
    0x90);

// Stream callouts for flow_classify hook
// c1ca9d8b-4d72-11ee-be56-0242ac120002
DEFINE_GUID(
    EBPF_HOOK_STREAM_FLOW_CLASSIFY_V4_CALLOUT,
    0xc1ca9d8b,
    0x4d72,
    0x11ee,
    0xbe,
    0x56,
    0x02,
    0x42,
    0xac,
    0x12,
    0x00,
    0x02);

// c1ca9f3e-4d72-11ee-be56-0242ac120002
DEFINE_GUID(
    EBPF_HOOK_STREAM_FLOW_CLASSIFY_V6_CALLOUT,
    0xc1ca9f3e,
    0x4d72,
    0x11ee,
    0xbe,
    0x56,
    0x02,
    0x42,
    0xac,
    0x12,
    0x00,
    0x02);

/**
 * @brief WFP classifyFn callback for EBPF_HOOK_FLOW_CLASSIFY_ALE_FLOW_ESTABLISHED_V4/6_CALLOUT.
 */
void
net_ebpf_extension_flow_classify_flow_established_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

/**
 * @brief WFP classifyFn callback for EBPF_HOOK_STREAM_FLOW_CLASSIFY_V4/6_CALLOUT.
 */
void
net_ebpf_extension_flow_classify_flow_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output);

/**
 * @brief WFP flowDeleteFn callback for EBPF_HOOK_STREAM_FLOW_CLASSIFY_V4/6_CALLOUT.
 */
void
net_ebpf_extension_flow_classify_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context);

/**
 * @brief Unregister FLOW_CLASSIFY NPI providers.
 *
 */
void
net_ebpf_ext_flow_classify_unregister_providers();

/**
 * @brief Register FLOW_CLASSIFY NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_ext_flow_classify_register_providers();
