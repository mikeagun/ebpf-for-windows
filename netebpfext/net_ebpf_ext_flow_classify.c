// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/*
 * @file
 * @brief This file implements the hook for the FLOW_CLASSIFY program type and associated attach types, on eBPF for
 * Windows. This implements a WFP stream-layer callout for flow classification.
 *
 */

#include "ebpf_shared_framework.h"
#include "net_ebpf_ext_flow_classify.h"

//
// WFP related types & globals for FLOW_CLASSIFY hook.
//

struct _net_ebpf_extension_flow_classify_wfp_filter_context;

typedef struct _net_ebpf_bpf_flow_classify
{
    EBPF_CONTEXT_HEADER;
    bpf_flow_classify_t context;
    uint64_t process_id;
} net_ebpf_flow_classify_t;

/**
 * @brief Custom context associated with WFP flows that are notified to eBPF programs.
 */
typedef struct _net_ebpf_extension_flow_classify_wfp_flow_context
{
    LIST_ENTRY link;                                         ///< Link to next flow context.
    net_ebpf_extension_flow_context_parameters_t parameters; ///< WFP flow parameters.
    struct _net_ebpf_extension_flow_classify_wfp_filter_context*
        filter_context;               ///< WFP filter context associated with this flow.
    net_ebpf_flow_classify_t context; ///< flow_classify context.
} net_ebpf_extension_flow_classify_wfp_flow_context_t;

typedef struct _net_ebpf_extension_flow_classify_wfp_flow_context_list
{
    uint32_t count;       ///< Number of flow contexts in the list.
    LIST_ENTRY list_head; ///< Head to the list of WFP flow contexts.
} net_ebpf_extension_flow_classify_wfp_flow_context_list_t;

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_flow_classify_wfp_ale_filter_parameters[] = {
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_FLOW_CLASSIFY_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
     L"net eBPF flow_classify flow established hook",
     L"net eBPF flow_classify flow established hook WFP filter"},
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
     NULL, // Default sublayer.
     &EBPF_HOOK_FLOW_CLASSIFY_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
     L"net eBPF flow_classify flow established hook",
     L"net eBPF flow_classify flow established hook WFP filter"}};

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_flow_classify_wfp_stream_filter_parameters[] = {
    {&FWPM_LAYER_STREAM_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_STREAM_FLOW_CLASSIFY_V4_CALLOUT,
     L"net eBPF flow_classify hook",
     L"net eBPF flow_classify hook WFP filter"},
    {&FWPM_LAYER_STREAM_V6,
     NULL, // Default sublayer.
     &EBPF_HOOK_STREAM_FLOW_CLASSIFY_V6_CALLOUT,
     L"net eBPF flow_classify hook",
     L"net eBPF flow_classify hook WFP filter"}};

#define NET_EBPF_FLOW_CLASSIFY_ALE_FILTER_COUNT \
    EBPF_COUNT_OF(_net_ebpf_extension_flow_classify_wfp_ale_filter_parameters)
#define NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT \
    EBPF_COUNT_OF(_net_ebpf_extension_flow_classify_wfp_stream_filter_parameters)

typedef struct _net_ebpf_extension_flow_classify_wfp_filter_context
{
    net_ebpf_extension_wfp_filter_context_t base;
    uint32_t compartment_id; ///< Compartment Id condition value for the filters (if any).
    KSPIN_LOCK lock;         ///< Lock for synchronization.
    _Guarded_by_(lock) net_ebpf_extension_flow_classify_wfp_flow_context_list_t
        flow_context_list; ///< List of flow contexts associated with WFP flows.
} net_ebpf_extension_flow_classify_wfp_filter_context_t;

//
// FLOW_CLASSIFY Global helper function implementation.
//
static uint64_t
_ebpf_flow_classify_get_current_pid_tgid(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const bpf_flow_classify_t* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);
    net_ebpf_flow_classify_t* flow_classify_ctx = CONTAINING_RECORD(ctx, net_ebpf_flow_classify_t, context);
    return (flow_classify_ctx->process_id << 32 | (uint32_t)(uintptr_t)PsGetCurrentThreadId());
}

//
// FLOW_CLASSIFY Program Information NPI Provider.
//

static const void* _ebpf_flow_classify_global_helper_functions[] = {(void*)_ebpf_flow_classify_get_current_pid_tgid};

static ebpf_helper_function_addresses_t _ebpf_flow_classify_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_flow_classify_global_helper_functions),
    (uint64_t*)_ebpf_flow_classify_global_helper_functions};

static ebpf_result_t
_ebpf_flow_classify_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_flow_classify_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

static ebpf_program_data_t _ebpf_flow_classify_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_flow_classify_program_info,
    .global_helper_function_addresses = &_ebpf_flow_classify_global_helper_function_address_table,
    .context_create = &_ebpf_flow_classify_context_create,
    .context_destroy = &_ebpf_flow_classify_context_destroy,
    .required_irql = DISPATCH_LEVEL,
    .capabilities = {0},
};

// Set the program type as the provider module id.
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_flow_classify_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_PROGRAM_TYPE_FLOW_CLASSIFY_GUID};

static net_ebpf_extension_program_info_provider_t* _ebpf_flow_classify_program_info_provider_context = NULL;

//
// FLOW_CLASSIFY Hook NPI Provider.
//

ebpf_attach_provider_data_t _net_ebpf_flow_classify_hook_provider_data = {
    EBPF_ATTACH_PROVIDER_DATA_HEADER, EBPF_PROGRAM_TYPE_FLOW_CLASSIFY_GUID, BPF_FLOW_CLASSIFY, BPF_LINK_TYPE_PLAIN};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_flow_classify_hook_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_ATTACH_TYPE_FLOW_CLASSIFY_GUID};

static net_ebpf_extension_hook_provider_t* _ebpf_flow_classify_hook_provider_context = NULL;

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
_net_ebpf_extension_flow_classify_create_filter_context(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context)
{
    NET_EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* local_filter_context = NULL;
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    FWPM_FILTER_CONDITION conditions[2] = {0}; // Space for compartment_id and protocol
    uint32_t condition_count = 0;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
    // TODO: Refactor netebpfext code so we don't need the extra temp filter id lists.
    net_ebpf_ext_wfp_filter_id_t* ale_filter_ids = NULL;
    net_ebpf_ext_wfp_filter_id_t* stream_filter_ids = NULL;
    const uint32_t total_filter_count =
        NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT + NET_EBPF_FLOW_CLASSIFY_ALE_FILTER_COUNT;
    net_ebpf_ext_wfp_filter_id_t* combined_filter_ids = NULL;

    if (client_data->data != NULL) {
        // Note: No need to validate the client data here, as it has already been validated by the caller.
        compartment_id = *(uint32_t*)client_data->data;
    }

    // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
        conditions[condition_count].fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
        conditions[condition_count].matchType = FWP_MATCH_EQUAL;
        conditions[condition_count].conditionValue.type = FWP_UINT32;
        conditions[condition_count].conditionValue.uint32 = compartment_id;
        condition_count++;
    }

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_flow_classify_wfp_filter_context_t),
        attaching_client,
        provider_context,
        (net_ebpf_extension_wfp_filter_context_t**)&local_filter_context);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    local_filter_context->compartment_id = compartment_id;
    local_filter_context->base.filter_ids_count =
        NET_EBPF_FLOW_CLASSIFY_ALE_FILTER_COUNT + NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT;
    KeInitializeSpinLock(&local_filter_context->lock);
    InitializeListHead(&local_filter_context->flow_context_list.list_head);

    // First, add stream filters (no TCP protocol condition needed for stream layer)
    result = net_ebpf_extension_add_wfp_filters(
        local_filter_context->base.wfp_engine_handle,
        NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT,
        _net_ebpf_extension_flow_classify_wfp_stream_filter_parameters,
        condition_count,
        (condition_count > 0) ? conditions : NULL,
        (net_ebpf_extension_wfp_filter_context_t*)local_filter_context,
        &stream_filter_ids);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    // Add TCP protocol condition for ALE filters
    conditions[condition_count].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[condition_count].matchType = FWP_MATCH_EQUAL;
    conditions[condition_count].conditionValue.type = FWP_UINT8;
    conditions[condition_count].conditionValue.uint8 = IPPROTO_TCP;
    condition_count++;

    // Add ALE filters with TCP protocol condition
    result = net_ebpf_extension_add_wfp_filters(
        local_filter_context->base.wfp_engine_handle,
        NET_EBPF_FLOW_CLASSIFY_ALE_FILTER_COUNT,
        _net_ebpf_extension_flow_classify_wfp_ale_filter_parameters,
        condition_count,
        conditions,
        (net_ebpf_extension_wfp_filter_context_t*)local_filter_context,
        &ale_filter_ids);
    if (result != EBPF_SUCCESS) {
        // Clean up stream filters on error
        net_ebpf_extension_delete_wfp_filters(
            local_filter_context->base.wfp_engine_handle,
            NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT,
            stream_filter_ids);
        NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);
    }

    // Combine both filter ID arrays into a single array
    combined_filter_ids = (net_ebpf_ext_wfp_filter_id_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_ext_wfp_filter_id_t) * total_filter_count, NET_EBPF_EXTENSION_POOL_TAG);
    if (combined_filter_ids == NULL) {
        // Clean up both filter arrays on error
        net_ebpf_extension_delete_wfp_filters(
            local_filter_context->base.wfp_engine_handle,
            NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT,
            stream_filter_ids);
        net_ebpf_extension_delete_wfp_filters(
            local_filter_context->base.wfp_engine_handle, NET_EBPF_FLOW_CLASSIFY_ALE_FILTER_COUNT, ale_filter_ids);
        result = EBPF_NO_MEMORY;
        NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);
    }

    // Copy stream filter IDs first
    memcpy(
        combined_filter_ids,
        stream_filter_ids,
        sizeof(net_ebpf_ext_wfp_filter_id_t) * NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT);

    // Copy ALE filter IDs next
    memcpy(
        &combined_filter_ids[NET_EBPF_FLOW_CLASSIFY_STREAM_FILTER_COUNT],
        ale_filter_ids,
        sizeof(net_ebpf_ext_wfp_filter_id_t) * NET_EBPF_FLOW_CLASSIFY_ALE_FILTER_COUNT);

    // Free the individual arrays and set the combined array
    ExFreePool(stream_filter_ids);
    stream_filter_ids = NULL;
    ExFreePool(ale_filter_ids);
    ale_filter_ids = NULL;
    local_filter_context->base.filter_ids = combined_filter_ids;
    combined_filter_ids = NULL;

    *filter_context = (net_ebpf_extension_wfp_filter_context_t*)local_filter_context;
    local_filter_context = NULL;

Exit:
    if (local_filter_context != NULL) {
        CLEAN_UP_FILTER_CONTEXT(&local_filter_context->base);
    }
    if (stream_filter_ids != NULL) {
        ExFreePool(stream_filter_ids);
    }
    if (ale_filter_ids != NULL) {
        ExFreePool(ale_filter_ids);
    }
    if (combined_filter_ids != NULL) {
        ExFreePool(combined_filter_ids);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static ebpf_result_t
_net_ebpf_extension_flow_classify_validate_client_data(
    _In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard)
{
    NET_EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    *is_wildcard = FALSE;

    // FLOW_CLASSIFY hook clients must always provide data.
    if (client_data == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Attach denied. client data not provided.");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (client_data->data_size > 0) {
        if ((client_data->data_size != sizeof(uint32_t)) || (client_data->data == NULL)) {
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                "Attach denied. Invalid client data.");
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
    } else {
        // If the client did not specify any attach parameters, we treat that as a wildcard compartment id.
        *is_wildcard = TRUE;
    }

Exit:
    return result;
}

static void
_net_ebpf_extension_flow_classify_delete_filter_context(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    net_ebpf_extension_flow_classify_wfp_filter_context_t* local_filter_context = NULL;
    KIRQL irql;
    LIST_ENTRY local_list_head;

    NET_EBPF_EXT_LOG_ENTRY();

    if (filter_context == NULL) {
        goto Exit;
    }

    local_filter_context = (net_ebpf_extension_flow_classify_wfp_filter_context_t*)filter_context;

    InitializeListHead(&local_list_head);
    net_ebpf_extension_delete_wfp_filters(
        filter_context->wfp_engine_handle,
        local_filter_context->base.filter_ids_count,
        local_filter_context->base.filter_ids);

    KeAcquireSpinLock(&local_filter_context->lock, &irql);
    if (local_filter_context->flow_context_list.count > 0) {

        LIST_ENTRY* entry = local_filter_context->flow_context_list.list_head.Flink;
        RemoveEntryList(&local_filter_context->flow_context_list.list_head);
        InitializeListHead(&local_filter_context->flow_context_list.list_head);
        AppendTailList(&local_list_head, entry);

        local_filter_context->flow_context_list.count = 0;
    }
    KeReleaseSpinLock(&local_filter_context->lock, irql);

    // Remove the flow context associated with the WFP flows.
    while (!IsListEmpty(&local_list_head)) {
        LIST_ENTRY* entry = RemoveHeadList(&local_list_head);
        InitializeListHead(entry);
        net_ebpf_extension_flow_classify_wfp_flow_context_t* flow_context =
            CONTAINING_RECORD(entry, net_ebpf_extension_flow_classify_wfp_flow_context_t, link);

        net_ebpf_extension_flow_context_parameters_t* flow_parameters = &flow_context->parameters;

        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowremovecontext0
        // Calling FwpsFlowRemoveContext may cause the flowDeleteFn callback on the callout to be invoked synchronously.
        // The net_ebpf_extension_flow_classify_flow_delete function frees the flow context memory and
        // releases reference on the filter_context.
        NTSTATUS status =
            FwpsFlowRemoveContext(flow_parameters->flow_id, flow_parameters->layer_id, flow_parameters->callout_id);
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "FwpsFlowRemoveContext", status);
        ASSERT(status == STATUS_SUCCESS);
    }

    net_ebpf_extension_wfp_filter_context_cleanup(filter_context);

Exit:
    NET_EBPF_EXT_LOG_EXIT();
}

NTSTATUS
net_ebpf_ext_flow_classify_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;
    const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_flow_classify_hook_provider_moduleid, &_net_ebpf_flow_classify_hook_provider_data};

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_flow_classify_program_info_provider_moduleid, &_ebpf_flow_classify_program_data};

    const net_ebpf_extension_hook_provider_dispatch_table_t dispatch_table = {
        .create_filter_context = _net_ebpf_extension_flow_classify_create_filter_context,
        .delete_filter_context = _net_ebpf_extension_flow_classify_delete_filter_context,
        .validate_client_data = _net_ebpf_extension_flow_classify_validate_client_data,
    };

    NET_EBPF_EXT_LOG_ENTRY();

    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_flow_classify_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "net_ebpf_extension_program_info_provider_register failed.",
            status);
        goto Exit;
    }

    // Register the flow_classify provider context
    status = net_ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        &dispatch_table,
        ATTACH_CAPABILITY_SINGLE_ATTACH_PER_HOOK,
        NULL,
        &_ebpf_flow_classify_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "net_ebpf_extension_hook_provider_register failed for flow_classify.",
            status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_ext_flow_classify_unregister_providers();
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_flow_classify_unregister_providers()
{
    NET_EBPF_EXT_LOG_ENTRY();
    if (_ebpf_flow_classify_hook_provider_context != NULL) {
        net_ebpf_extension_hook_provider_unregister(_ebpf_flow_classify_hook_provider_context);
        _ebpf_flow_classify_hook_provider_context = NULL;
    }
    if (_ebpf_flow_classify_program_info_provider_context != NULL) {
        net_ebpf_extension_program_info_provider_unregister(_ebpf_flow_classify_program_info_provider_context);
        _ebpf_flow_classify_program_info_provider_context = NULL;
    }
}

// //
// // NMR Registration Helper Routines.
// //
//
// static ebpf_result_t
// _net_ebpf_extension_flow_cleanup_create_filter_context(
//     _In_ const net_ebpf_extension_hook_client_t* attaching_client,
//     _In_ const net_ebpf_extension_hook_provider_t* provider_context,
//     _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context)
// {
//     NET_EBPF_EXT_LOG_ENTRY();
//     ebpf_result_t result = EBPF_SUCCESS;
//     net_ebpf_extension_flow_classify_wfp_filter_context_t* local_filter_context = NULL;
//     uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
//     FWPM_FILTER_CONDITION conditions[2] = {0}; // Space for compartment_id and protocol
//     uint32_t condition_count = 0;
//     const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
//
//     if (client_data->data != NULL) {
//         // Note: No need to validate the client data here, as it has already been validated by the caller.
//         compartment_id = *(uint32_t*)client_data->data;
//     }
//
//     // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
//     if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
//         conditions[condition_count].fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
//         conditions[condition_count].matchType = FWP_MATCH_EQUAL;
//         conditions[condition_count].conditionValue.type = FWP_UINT32;
//         conditions[condition_count].conditionValue.uint32 = compartment_id;
//         condition_count++;
//     }
//
//     // Add TCP protocol condition for flow cleanup (only interested in TCP flows)
//     conditions[condition_count].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
//     conditions[condition_count].matchType = FWP_MATCH_EQUAL;
//     conditions[condition_count].conditionValue.type = FWP_UINT8;
//     conditions[condition_count].conditionValue.uint8 = IPPROTO_TCP;
//     condition_count++;
//
//     result = net_ebpf_extension_wfp_filter_context_create(
//         sizeof(net_ebpf_extension_flow_classify_wfp_filter_context_t),
//         attaching_client,
//         provider_context,
//         (net_ebpf_extension_wfp_filter_context_t**)&local_filter_context);
//     NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);
//
//     local_filter_context->compartment_id = compartment_id;
//     local_filter_context->base.filter_ids_count = NET_EBPF_FLOW_CLEANUP_FILTER_COUNT;
//     KeInitializeSpinLock(&local_filter_context->lock);
//     InitializeListHead(&local_filter_context->flow_context_list.list_head);
//
//     // Add cleanup filters with TCP protocol condition
//     result = net_ebpf_extension_add_wfp_filters(
//         local_filter_context->base.wfp_engine_handle,
//         NET_EBPF_FLOW_CLEANUP_FILTER_COUNT,
//         _net_ebpf_extension_flow_cleanup_wfp_filter_parameters,
//         condition_count,
//         conditions,
//         (net_ebpf_extension_wfp_filter_context_t*)local_filter_context,
//         &local_filter_context->base.filter_ids);
//     NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);
//
//     *filter_context = (net_ebpf_extension_wfp_filter_context_t*)local_filter_context;
//     local_filter_context = NULL;
//
// Exit:
//     if (local_filter_context != NULL) {
//         CLEAN_UP_FILTER_CONTEXT(&local_filter_context->base);
//     }
//
//     NET_EBPF_EXT_RETURN_RESULT(result);
// }
//
// static ebpf_result_t
// _net_ebpf_extension_flow_cleanup_validate_client_data(
//     _In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard)
// {
//     NET_EBPF_EXT_LOG_ENTRY();
//     ebpf_result_t result = EBPF_SUCCESS;
//     *is_wildcard = FALSE;
//
//     // FLOW_CLEANUP hook clients must always provide data.
//     if (client_data == NULL) {
//         NET_EBPF_EXT_LOG_MESSAGE(
//             NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
//             NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
//             "Attach denied. client data not provided for flow cleanup.");
//         result = EBPF_INVALID_ARGUMENT;
//         goto Exit;
//     }
//
//     if (client_data->data_size > 0) {
//         if ((client_data->data_size != sizeof(uint32_t)) || (client_data->data == NULL)) {
//             NET_EBPF_EXT_LOG_MESSAGE(
//                 NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
//                 NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
//                 "Attach denied. Invalid client data for flow cleanup.");
//             result = EBPF_INVALID_ARGUMENT;
//             goto Exit;
//         }
//     } else {
//         // If the client did not specify any attach parameters, we treat that as a wildcard compartment id.
//         *is_wildcard = TRUE;
//     }
//
// Exit:
//     return result;
// }

void
net_ebpf_extension_flow_classify_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context)
{
    net_ebpf_extension_flow_classify_wfp_flow_context_t* local_flow_context =
        (net_ebpf_extension_flow_classify_wfp_flow_context_t*)(uintptr_t)flow_context;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* filter_context = NULL;
    bpf_flow_classify_t* flow_classify_context = NULL;
    uint32_t result = 0;
    ebpf_result_t program_result;
    KIRQL irql = 0;

    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);

    NET_EBPF_EXT_LOG_ENTRY();

    if (local_flow_context == NULL) {
        goto Exit;
    }

    filter_context = local_flow_context->filter_context;
    if (filter_context == NULL) {
        goto Exit;
    }

    if (filter_context->base.context_deleting) {
        goto Exit;
    }

    // Get the flow classify context
    flow_classify_context = &local_flow_context->context.context;

    // Invoke the flow_cleanup eBPF program if attached
    if (flow_classify_context->state == FLOW_STATE_NEW) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Empty flow deleted",
            flow_classify_context->flow_id);
    } else {
        flow_classify_context->data_start = NULL;
        flow_classify_context->data_end = NULL;
        flow_classify_context->state = FLOW_STATE_DELETED;
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_INFO,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Invoking eBPF cleanup program",
            flow_classify_context->flow_id);

        program_result = net_ebpf_extension_hook_invoke_programs(flow_classify_context, &filter_context->base, &result);
        if (program_result == EBPF_OBJECT_NOT_FOUND) {
            // No cleanup program attached, continue with normal cleanup
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
                NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                "No cleanup program attached");
        } else if (program_result != EBPF_SUCCESS) {
            NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                "net_ebpf_extension_hook_invoke_programs failed for cleanup",
                program_result);
        }
    }

    // Remove from filter context's flow list
    KeAcquireSpinLock(&filter_context->lock, &irql);
    RemoveEntryList(&local_flow_context->link);
    filter_context->flow_context_list.count--;
    KeReleaseSpinLock(&filter_context->lock, irql);

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
        "Flow cleanup completed.",
        local_flow_context->parameters.flow_id);

Exit:
    if (filter_context) {
        DEREFERENCE_FILTER_CONTEXT(&filter_context->base);
    }

    if (local_flow_context != NULL) {
        ExFreePool(local_flow_context);
    }

    NET_EBPF_EXT_LOG_EXIT();
}

extern wfp_ale_layer_fields_t wfp_flow_established_fields[2]; // Used for flow established hooks

/**
 * @brief Copy WFP connection fields from ALE layer to flow_classify context.
 *
 * @param[in] incoming_fixed_values WFP incoming fixed values.
 * @param[in] incoming_metadata_values WFP incoming metadata values.
 * @param[out] flow_classify_context Flow classify context to populate.
 */
static void
_net_ebpf_extension_flow_classify_copy_wfp_connection_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Out_ net_ebpf_flow_classify_t* flow_classify_context)
{
    NET_EBPF_EXT_LOG_ENTRY();
    uint16_t wfp_layer_id = incoming_fixed_values->layerId;
    net_ebpf_extension_hook_id_t hook_id = net_ebpf_extension_get_hook_id_from_wfp_layer_id(wfp_layer_id);
    wfp_ale_layer_fields_t* fields = &wfp_flow_established_fields[hook_id - EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4];
    bpf_flow_classify_t* flow_classify = &flow_classify_context->context;

    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    // Set direction
    flow_classify->direction = (uint8_t)(incoming_values[fields->direction_field].value.uint32 == FWP_DIRECTION_OUTBOUND
                                             ? FLOW_DIRECTION_OUTBOUND
                                             : FLOW_DIRECTION_INBOUND);

    // Copy IP address fields.
    if (hook_id == EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4) {
        flow_classify->family = AF_INET;
        flow_classify->local_ip4 = htonl(incoming_values[fields->local_ip_address_field].value.uint32);
        flow_classify->remote_ip4 = htonl(incoming_values[fields->remote_ip_address_field].value.uint32);
    } else if (hook_id == EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6) {
        flow_classify->family = AF_INET6;
        RtlCopyMemory(
            flow_classify->local_ip6,
            incoming_values[fields->local_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
        RtlCopyMemory(
            flow_classify->remote_ip6,
            incoming_values[fields->remote_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
    } else {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "flow_established: Invalid hook_id",
            hook_id);
        return;
    }
    flow_classify->local_port = htons(incoming_values[fields->local_port_field].value.uint16);
    flow_classify->remote_port = htons(incoming_values[fields->remote_port_field].value.uint16);
    flow_classify->protocol = incoming_values[fields->protocol_field].value.uint8;
    flow_classify->compartment_id = incoming_values[fields->compartment_id_field].value.uint32;
    flow_classify->interface_luid = *incoming_values[fields->interface_luid_field].value.uint64;

    // Set flow ID (will be set later when we have the flow handle)
    flow_classify->flow_id = 0;

    // Stream data pointers (will be set in stream callback)
    flow_classify->data_start = NULL;
    flow_classify->data_end = NULL;

    // Process ID from metadata
    if (incoming_metadata_values->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        flow_classify_context->process_id = incoming_metadata_values->processId;
    } else {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "FWPS_METADATA_FIELD_PROCESS_ID not present",
            hook_id);

        flow_classify_context->process_id = 0;
    }
}

// WFP stream layer field definitions for flow classify
wfp_stream_layer_fields_t wfp_stream_fields[] = {
    // EBPF_HOOK_STREAM_V4
    {FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT,
     FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT,
     0, // No protocol field in stream layer - will get from connection state
     FWPS_FIELD_STREAM_V4_DIRECTION,
     FWPS_FIELD_STREAM_V4_COMPARTMENT_ID,
     0,  // No interface field in stream layer - will leave as 0
     0}, // Stream data is in layer_data parameter
    // EBPF_HOOK_STREAM_V6
    {FWPS_FIELD_STREAM_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_STREAM_V6_IP_LOCAL_PORT,
     FWPS_FIELD_STREAM_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_STREAM_V6_IP_REMOTE_PORT,
     0, // No protocol field in stream layer - will get from connection state
     FWPS_FIELD_STREAM_V6_DIRECTION,
     FWPS_FIELD_STREAM_V6_COMPARTMENT_ID,
     0,   // No interface field in stream layer - will leave as 0
     0}}; // Stream data is in layer_data parameter

static void
_net_ebpf_extension_flow_classify_copy_wfp_stream_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_ void* layer_data,
    _Out_ net_ebpf_flow_classify_t* flow_classify_context)
{
    UNREFERENCED_PARAMETER(layer_data); // Currently copied in flow_classify callout.
    NET_EBPF_EXT_LOG_ENTRY();
    uint16_t wfp_layer_id = incoming_fixed_values->layerId;
    net_ebpf_extension_hook_id_t hook_id = net_ebpf_extension_get_hook_id_from_wfp_layer_id(wfp_layer_id);
    wfp_stream_layer_fields_t* fields = &wfp_stream_fields[hook_id - EBPF_HOOK_STREAM_V4];
    bpf_flow_classify_t* flow_classify = &flow_classify_context->context;

    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    // Set direction
    flow_classify->direction = (uint8_t)(incoming_values[fields->direction_field].value.uint32 == FWP_DIRECTION_OUTBOUND
                                             ? FLOW_DIRECTION_OUTBOUND
                                             : FLOW_DIRECTION_INBOUND);
    // Note: we get protocol/src/dest IP/port at flow established layer, so we don't need to copy them here.
    // // Copy IP address fields
    // if (hook_id == EBPF_HOOK_STREAM_V4) {
    //     flow_classify->family = AF_INET;
    //     flow_classify->local_ip4 = htonl(incoming_values[fields->local_ip_address_field].value.uint32);
    //     flow_classify->remote_ip4 = htonl(incoming_values[fields->remote_ip_address_field].value.uint32);
    // } else if (hook_id == EBPF_HOOK_STREAM_V6) {
    //     flow_classify->family = AF_INET6;
    //     RtlCopyMemory(
    //         flow_classify->local_ip6,
    //         incoming_values[fields->local_ip_address_field].value.byteArray16,
    //         sizeof(FWP_BYTE_ARRAY16));
    //     RtlCopyMemory(
    //         flow_classify->remote_ip6,
    //         incoming_values[fields->remote_ip_address_field].value.byteArray16,
    //         sizeof(FWP_BYTE_ARRAY16));
    // } else {
    //     NET_EBPF_EXT_LOG_MESSAGE_UINT64(
    //         NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "Invalid hook_id",
    //         hook_id);
    //     return;
    // }

    // flow_classify->local_port = htons(incoming_values[fields->local_port_field].value.uint16);
    // flow_classify->remote_port = htons(incoming_values[fields->remote_port_field].value.uint16);

    // // Protocol and interface fields not available at stream layer
    // // For TCP streams, protocol is always TCP (6)
    // flow_classify->protocol = IPPROTO_TCP;

    // flow_classify->compartment_id = incoming_values[fields->compartment_id_field].value.uint32;
    // flow_classify->interface_luid = 0; // Not available at stream layer

    // Update flow ID if available
    if (incoming_metadata_values->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) {
        flow_classify->flow_id = incoming_metadata_values->flowHandle;
    } else {
        flow_classify->flow_id = 0;
    }

    // Set process ID
    if (incoming_metadata_values->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        flow_classify_context->process_id = incoming_metadata_values->processId;
    } else {
        flow_classify_context->process_id = 0;
    }
}

//
// WFP callout callback function for stream layer.
//
void
net_ebpf_extension_flow_classify_flow_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NTSTATUS status = STATUS_SUCCESS;
    uint32_t result = FLOW_CLASSIFY_ALLOW;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_flow_classify_wfp_flow_context_t* local_flow_context = NULL;
    bpf_flow_classify_t* flow_classify_context = NULL;
    uint32_t client_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    ebpf_result_t program_result;
    uint8_t* allocated_data_buffer = NULL; // Track allocated buffer for cleanup

    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(incoming_fixed_values);

    NET_EBPF_EXT_LOG_ENTRY();

    NET_EBPF_EXT_LOG_MESSAGE(
        NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "in flow_classify callback");

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
        "flow id",
        incoming_metadata_values->flowHandle);

    // Default action is to permit
    classify_output->rights |= FWPS_RIGHT_ACTION_WRITE;
    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_flow_classify_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "filter_context is NULL");
        goto Exit;
    }

    if (filter_context->base.context_deleting) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "filter_context is being deleted");
        goto Exit;
    }

    local_flow_context = (net_ebpf_extension_flow_classify_wfp_flow_context_t*)(uintptr_t)flow_context;

    // Get flow context - should always be present due to FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW
    if (local_flow_context == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Stream callout invoked without flow context");
        goto Exit;
    }

    // Update stream layer fields in flow classify context
    // (Most connection fields were already set in flow_established callback)
    _net_ebpf_extension_flow_classify_copy_wfp_stream_fields(
        incoming_fixed_values, incoming_metadata_values, layer_data, &local_flow_context->context);

    // Copy WFP stream fields to the flow classify context
    flow_classify_context = &local_flow_context->context.context;

    // Set stream data pointers for this segment
    if (layer_data != NULL) {
        // layer_data is a pointer to FWPS_STREAM_DATA0 at the stream layer
        FWPS_STREAM_DATA0* stream_data = ((FWPS_STREAM_CALLOUT_IO_PACKET0*)layer_data)->streamData;

        flow_classify_context->direction =
            (uint8_t)(stream_data->flags & FWPS_STREAM_FLAG_SEND ? FLOW_DIRECTION_OUTBOUND : FLOW_DIRECTION_INBOUND);

        if (stream_data->netBufferListChain != NULL && stream_data->dataLength > 0) {
            // Get the first NET_BUFFER from the NET_BUFFER_LIST chain
            NET_BUFFER_LIST* nbl = stream_data->netBufferListChain;
            NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);

            if (net_buffer != NULL) {
                // Try to get contiguous data buffer from the NET_BUFFER
                uint8_t* buffer = (uint8_t*)NdisGetDataBuffer(net_buffer, (ULONG)stream_data->dataLength, NULL, 1, 0);

                if (buffer != NULL) {
                    // Data is already contiguous
                    flow_classify_context->data_start = buffer;
                    flow_classify_context->data_end = buffer + stream_data->dataLength;
                } else {
                    // Data is not contiguous - allocate buffer and copy using WFP function
                    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
                        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
                        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                        "Stream data is not contiguous, copying to buffer. Length:",
                        stream_data->dataLength);

                    allocated_data_buffer = (uint8_t*)ExAllocatePoolUninitialized(
                        NonPagedPoolNx, (SIZE_T)stream_data->dataLength, NET_EBPF_EXTENSION_POOL_TAG);

                    if (allocated_data_buffer != NULL) {
                        SIZE_T bytes_copied = 0;
                        FwpsCopyStreamDataToBuffer0(
                            stream_data, allocated_data_buffer, (SIZE_T)stream_data->dataLength, &bytes_copied);

                        if (bytes_copied == stream_data->dataLength) {
                            flow_classify_context->data_start = allocated_data_buffer;
                            flow_classify_context->data_end = allocated_data_buffer + stream_data->dataLength;
                        } else {
                            NET_EBPF_EXT_LOG_MESSAGE_UINT64(
                                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                                NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                                "FwpsCopyStreamDataToBuffer0 copied unexpected amount",
                                bytes_copied);
                            ExFreePool(allocated_data_buffer);
                            allocated_data_buffer = NULL;
                            flow_classify_context->data_start = NULL;
                            flow_classify_context->data_end = NULL;
                        }
                    } else {
                        NET_EBPF_EXT_LOG_MESSAGE(
                            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                            "Failed to allocate buffer for non-contiguous stream data");
                        flow_classify_context->data_start = NULL;
                        flow_classify_context->data_end = NULL;
                    }
                }
            } else {
                NET_EBPF_EXT_LOG_MESSAGE(
                    NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                    "No NET_BUFFER in stream data");
                flow_classify_context->data_start = NULL;
                flow_classify_context->data_end = NULL;
            }
        } else {
            // No actual data in this stream segment
            flow_classify_context->data_start = NULL;
            flow_classify_context->data_end = NULL;
        }
    } else {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "No stream data available");
        flow_classify_context->data_start = NULL;
        flow_classify_context->data_end = NULL;
        goto Exit;
    }

    // Check compartment ID if specified
    client_compartment_id = local_flow_context->filter_context->compartment_id;
    if (client_compartment_id != UNSPECIFIED_COMPARTMENT_ID &&
        client_compartment_id != flow_classify_context->compartment_id) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Compartment id mismatch",
            client_compartment_id);
        goto Exit;
    }

    NET_EBPF_EXT_LOG_MESSAGE(
        NET_EBPF_EXT_TRACELOG_LEVEL_INFO, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "Invoking eBPF program");
    // Invoke the eBPF program
    program_result = net_ebpf_extension_hook_invoke_programs(
        flow_classify_context, &local_flow_context->filter_context->base, &result);
    if (program_result == EBPF_OBJECT_NOT_FOUND) {
        // No program attached, allow
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "No program attached, allowing flow");
        goto Exit;
    } else if (program_result != EBPF_SUCCESS) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "net_ebpf_extension_hook_invoke_programs failed",
            program_result);
        goto Exit;
    }

    // Handle the program result
    switch (result) {
    case FLOW_CLASSIFY_ALLOW:
        // classify_output->rights |= FWPS_RIGHT_ACTION_WRITE;
        classify_output->actionType = FWP_ACTION_PERMIT;
        classify_output->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

        // Remove the WFP context - program has decided, no more classifications needed
        // Note: FwpsFlowRemoveContext will trigger the flow delete callback which cleans up the context
        status = FwpsFlowRemoveContext(
            local_flow_context->parameters.flow_id,
            local_flow_context->parameters.layer_id,
            local_flow_context->parameters.callout_id);

        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                NET_EBPF_EXT_TRACELOG_LEVEL_WARNING,
                NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                "FwpsFlowRemoveContext failed on ALLOW",
                status);
            // Even if removal fails, we don't want to continue classifying
            // The context will be cleaned up when the flow ends naturally
        }

        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Flow allowed permanently");
        break;

    case FLOW_CLASSIFY_BLOCK:
        // Block the segment and kill the flow
        // classify_output->rights |= FWPS_RIGHT_ACTION_WRITE;
        classify_output->actionType = FWP_ACTION_BLOCK;
        classify_output->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

        // Remove the WFP context - flow is being blocked
        // Note: FwpsFlowRemoveContext will trigger the flow delete callback which cleans up the context
        status = FwpsFlowRemoveContext(
            local_flow_context->parameters.flow_id,
            local_flow_context->parameters.layer_id,
            local_flow_context->parameters.callout_id);

        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                NET_EBPF_EXT_TRACELOG_LEVEL_WARNING,
                NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
                "FwpsFlowRemoveContext failed on BLOCK",
                status);
            // Even if removal fails, the flow is being blocked anyway
            // The context will be cleaned up when the flow ends naturally
        }

        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "Flow blocked");
        break;

    case FLOW_CLASSIFY_NEED_MORE_DATA:
    default:
        // Allow the segment but keep classifying future segments
        classify_output->actionType = FWP_ACTION_PERMIT;
        flow_classify_context->state = FLOW_STATE_ESTABLISHED;

        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Need more data, continuing classification");
        break;
    }

Exit:
    // Clean up allocated data buffer if one was created
    if (allocated_data_buffer != NULL) {
        ExFreePool(allocated_data_buffer);
        allocated_data_buffer = NULL;
    }

    NET_EBPF_EXT_LOG_EXIT();
}

void
net_ebpf_extension_flow_classify_flow_delete_old(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context)
{
    net_ebpf_extension_flow_classify_wfp_flow_context_t* local_flow_context =
        (net_ebpf_extension_flow_classify_wfp_flow_context_t*)(uintptr_t)flow_context;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* filter_context = NULL;
    KIRQL irql = 0;

    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);

    NET_EBPF_EXT_LOG_ENTRY();

    if (local_flow_context == NULL) {
        goto Exit;
    }

    filter_context = local_flow_context->filter_context;
    if (filter_context == NULL) {
        goto Exit;
    }

    if (filter_context->base.context_deleting) {
        goto Exit;
    }

    KeAcquireSpinLock(&filter_context->lock, &irql);
    RemoveEntryList(&local_flow_context->link);
    filter_context->flow_context_list.count--;
    KeReleaseSpinLock(&filter_context->lock, irql);

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
        "Flow deleted.",
        local_flow_context->parameters.flow_id);

Exit:
    if (filter_context) {
        DEREFERENCE_FILTER_CONTEXT(&filter_context->base);
    }

    if (local_flow_context != NULL) {
        ExFreePool(local_flow_context);
    }

    NET_EBPF_EXT_LOG_EXIT();
}

static ebpf_result_t
_ebpf_flow_classify_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    NET_EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    bpf_flow_classify_t* flow_classify_context = NULL;
    net_ebpf_flow_classify_t* context_header = NULL;

    *context = NULL;

    // This provider requires data.
    if (data_in == NULL || data_size_in == 0) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "Data is not supported");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // This provider requires context.
    if (context_in == NULL || context_size_in < sizeof(bpf_flow_classify_t)) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    context_header = (net_ebpf_flow_classify_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_flow_classify_t), NET_EBPF_EXTENSION_POOL_TAG);

    if (context_header == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    flow_classify_context = &context_header->context;

    memcpy(flow_classify_context, context_in, sizeof(bpf_flow_classify_t));
    flow_classify_context->data_start = (uint8_t*)data_in;
    flow_classify_context->data_end = (uint8_t*)data_in + data_size_in;

    *context = flow_classify_context;
    context_header = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (context_header != NULL) {
        ExFreePool(context_header);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_flow_classify_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    NET_EBPF_EXT_LOG_ENTRY();
    net_ebpf_flow_classify_t* context_header = NULL;

    UNREFERENCED_PARAMETER(data_out);
    if (context == NULL) {
        goto Exit;
    }
    context_header = CONTAINING_RECORD(context, net_ebpf_flow_classify_t, context);

    // This provider doesn't support data.

    *data_size_out = 0;

    if (context_out != NULL && *context_size_out >= sizeof(bpf_flow_classify_t)) {
        memcpy(context_out, context, sizeof(bpf_flow_classify_t));
        *context_size_out = sizeof(bpf_flow_classify_t);
    } else {
        *context_size_out = 0;
    }

    ExFreePool(context_header);
Exit:
    NET_EBPF_EXT_LOG_EXIT();
}

//
// WFP callout callback function for ALE flow established layer (sets up context for stream classification).
//
void
net_ebpf_extension_flow_classify_flow_established_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NTSTATUS status = STATUS_SUCCESS;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_flow_classify_wfp_flow_context_t* local_flow_context = NULL;
    uint32_t client_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_hook_id_t hook_id =
        net_ebpf_extension_get_hook_id_from_wfp_layer_id(incoming_fixed_values->layerId);
    KIRQL old_irql = PASSIVE_LEVEL;
    wfp_ale_layer_fields_t* fields = &wfp_flow_established_fields[hook_id - EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4];
    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    NET_EBPF_EXT_LOG_ENTRY();
    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
        "flow id",
        incoming_metadata_values->flowHandle);

    // Default action is to permit
    classify_output->rights |= FWPS_RIGHT_ACTION_WRITE;
    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_flow_classify_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "filter_context is NULL");
        goto Exit;
    }

    if (filter_context->base.context_deleting) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "filter_context is being deleted");
        goto Exit;
    }

    // Check compartment ID if specified
    client_compartment_id = filter_context->compartment_id;
    if (client_compartment_id != UNSPECIFIED_COMPARTMENT_ID &&
        client_compartment_id != incoming_values[fields->compartment_id_field].value.uint32) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Compartment id mismatch in flow established",
            client_compartment_id);
        goto Exit;
    }

    // Check if this is a TCP flow - we only want to set up context for TCP flows
    if (incoming_values[fields->protocol_field].value.uint8 != IPPROTO_TCP) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Non-TCP flow, skipping context setup",
            incoming_values[fields->protocol_field].value.uint8);
        goto Exit;
    }

    // Create flow context for this flow
    local_flow_context = (net_ebpf_extension_flow_classify_wfp_flow_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_flow_classify_wfp_flow_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    if (local_flow_context == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "Failed to allocate flow context");
        goto Exit;
    }

    memset(local_flow_context, 0, sizeof(net_ebpf_extension_flow_classify_wfp_flow_context_t));

    // Associate the filter context with the local flow context
    REFERENCE_FILTER_CONTEXT(&filter_context->base);
    local_flow_context->filter_context = filter_context;

    // Set up flow parameters for the stream layer
    local_flow_context->parameters.flow_id = incoming_metadata_values->flowHandle;
    local_flow_context->parameters.layer_id =
        (uint16_t)((hook_id == EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4) ? FWPS_LAYER_STREAM_V4 : FWPS_LAYER_STREAM_V6);
    local_flow_context->parameters.callout_id = (hook_id == EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4)
                                                    ? net_ebpf_extension_get_callout_id_for_hook(EBPF_HOOK_STREAM_V4)
                                                    : net_ebpf_extension_get_callout_id_for_hook(EBPF_HOOK_STREAM_V6);

    // Initialize the flow classify context with ALE layer data
    _net_ebpf_extension_flow_classify_copy_wfp_connection_fields(
        incoming_fixed_values, incoming_metadata_values, &local_flow_context->context);

    // Set the flow ID after copying other fields
    local_flow_context->context.context.flow_id = incoming_metadata_values->flowHandle;

    local_flow_context->context.context.state = FLOW_STATE_NEW;

    if (flow_context != 0) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "Flow context already set");
    }

    // Associate the flow context with the stream layer callout
    status = FwpsFlowAssociateContext(
        local_flow_context->parameters.flow_id,
        local_flow_context->parameters.layer_id,
        local_flow_context->parameters.callout_id,
        (uint64_t)(uintptr_t)local_flow_context);

    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "FwpsFlowAssociateContext failed in flow established",
            status);
        goto Exit;
    }

    // tracelog flow_id, layer_id, callout_id
    NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
        "FwpsFlowAssociateContext succeeded",
        local_flow_context->parameters.flow_id,
        local_flow_context->parameters.layer_id,
        local_flow_context->parameters.callout_id);

    // Add to the flow context list
    KeAcquireSpinLock(&filter_context->lock, &old_irql);
    InsertTailList(&filter_context->flow_context_list.list_head, &local_flow_context->link);
    filter_context->flow_context_list.count++;
    KeReleaseSpinLock(&filter_context->lock, old_irql);

    local_flow_context = NULL; // Successfully associated

    NET_EBPF_EXT_LOG_MESSAGE(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
        "Flow context set up for stream classification");

Exit:
    if (local_flow_context != NULL) {
        // Failed to associate context, clean up
        if (local_flow_context->filter_context) {
            DEREFERENCE_FILTER_CONTEXT(&local_flow_context->filter_context->base);
        }
        ExFreePool(local_flow_context);
    }

    NET_EBPF_EXT_LOG_EXIT();
}
