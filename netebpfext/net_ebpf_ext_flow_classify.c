// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// FIXME: This is a currently a duplicate of net_ebpf_ext_sock_ops.c (doesn't implement flow classify yet).

/*
 * @file
 * @brief This file implements the hook for the FLOW_CLASSIFY program type and associated attach types, on eBPF for
 * Windows.
 *
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

const net_ebpf_extension_wfp_filter_parameters_t _net_ebpf_extension_flow_classify_wfp_filter_parameters[] = {
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_STREAM_CLASSIFY_V4_CALLOUT,
     L"net eBPF flow_classify hook",
     L"net eBPF flow_classify hook WFP filter"},
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_STREAM_CLASSIFY_V6_CALLOUT,
     L"net eBPF flow_classify hook",
     L"net eBPF flow_classify hook WFP filter"}};

#define NET_EBPF_FLOW_CLASSIFY_FILTER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_flow_classify_wfp_filter_parameters)

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
    // .program_info = &_ebpf_flow_classify_program_info,
    .program_info = &_ebpf_sock_ops_program_info,
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
    EBPF_ATTACH_PROVIDER_DATA_HEADER, EBPF_PROGRAM_TYPE_FLOW_CLASSIFY_GUID, BPF_FLOW_CLASSIFY, BPF_LINK_TYPE_CGROUP};

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
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* local_filter_context = NULL;
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    uint32_t filter_count;
    FWPM_FILTER_CONDITION condition = {0};
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);

    if (client_data->data != NULL) {
        // Note: No need to validate the client data here, as it has already been validated by the caller.
        compartment_id = *(uint32_t*)client_data->data;
    }

    // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
        condition.fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = compartment_id;
    }

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_flow_classify_wfp_filter_context_t),
        attaching_client,
        provider_context,
        (net_ebpf_extension_wfp_filter_context_t**)&local_filter_context);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    local_filter_context->compartment_id = compartment_id;
    local_filter_context->base.filter_ids_count = NET_EBPF_FLOW_CLASSIFY_FILTER_COUNT;
    KeInitializeSpinLock(&local_filter_context->lock);
    InitializeListHead(&local_filter_context->flow_context_list.list_head);

    // Add WFP filters at appropriate layers and set the hook NPI client as the filter's raw context.
    filter_count = NET_EBPF_FLOW_CLASSIFY_FILTER_COUNT;
    result = net_ebpf_extension_add_wfp_filters(
        local_filter_context->base.wfp_engine_handle,
        filter_count,
        _net_ebpf_extension_flow_classify_wfp_filter_parameters,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? 0 : 1,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? NULL : &condition,
        (net_ebpf_extension_wfp_filter_context_t*)local_filter_context,
        &local_filter_context->base.filter_ids);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    *filter_context = (net_ebpf_extension_wfp_filter_context_t*)local_filter_context;
    local_filter_context = NULL;

Exit:
    if (local_filter_context != NULL) {
        CLEAN_UP_FILTER_CONTEXT(&local_filter_context->base);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static ebpf_result_t
_net_ebpf_extension_flow_classify_validate_client_data(
    _In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard)
{
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

    // Register the provider context and pass the pointer to the WFP filter parameters
    // corresponding to this hook type as custom data.
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
            "net_ebpf_extension_hook_provider_register failed.",
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
    if (_ebpf_flow_classify_hook_provider_context != NULL) {
        net_ebpf_extension_hook_provider_unregister(_ebpf_flow_classify_hook_provider_context);
        _ebpf_flow_classify_hook_provider_context = NULL;
    }
    if (_ebpf_flow_classify_program_info_provider_context != NULL) {
        net_ebpf_extension_program_info_provider_unregister(_ebpf_flow_classify_program_info_provider_context);
        _ebpf_flow_classify_program_info_provider_context = NULL;
    }
}

extern wfp_ale_layer_fields_t wfp_flow_established_fields[2]; // FIXME: temporary hack
//     // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4
//     {FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_COMPARTMENT_ID,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_INTERFACE},
//     // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6
//     {FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_COMPARTMENT_ID,
//      FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_INTERFACE}};

static void
_net_ebpf_extension_flow_classify_copy_wfp_connection_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Out_ net_ebpf_flow_classify_t* flow_classify_context)
{
    uint16_t wfp_layer_id = incoming_fixed_values->layerId;
    net_ebpf_extension_hook_id_t hook_id = net_ebpf_extension_get_hook_id_from_wfp_layer_id(wfp_layer_id);
    wfp_ale_layer_fields_t* fields = &wfp_flow_established_fields[hook_id - EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4];
    bpf_flow_classify_t* flow_classify = &flow_classify_context->context;

    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    flow_classify->op = (incoming_values[fields->direction_field].value.uint32 == FWP_DIRECTION_OUTBOUND)
                            ? BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
                            : BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB;

    // Copy IP address fields.
    if (hook_id == EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4) {
        flow_classify->family = AF_INET;
        flow_classify->local_ip4 = htonl(incoming_values[fields->local_ip_address_field].value.uint32);
        flow_classify->remote_ip4 = htonl(incoming_values[fields->remote_ip_address_field].value.uint32);
    } else {
        flow_classify->family = AF_INET6;
        RtlCopyMemory(
            flow_classify->local_ip6,
            incoming_values[fields->local_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
        RtlCopyMemory(
            flow_classify->remote_ip6,
            incoming_values[fields->remote_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
    }
    flow_classify->local_port = htons(incoming_values[fields->local_port_field].value.uint16);
    flow_classify->remote_port = htons(incoming_values[fields->remote_port_field].value.uint16);
    flow_classify->protocol = incoming_values[fields->protocol_field].value.uint8;
    flow_classify->compartment_id = incoming_values[fields->compartment_id_field].value.uint32;
    flow_classify->interface_luid = *incoming_values[fields->interface_luid_field].value.uint64;
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

//
// WFP callout callback function.
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
    NTSTATUS status;
    uint32_t result;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_flow_classify_wfp_flow_context_t* local_flow_context = NULL;
    bpf_flow_classify_t* flow_classify_context = NULL;
    uint32_t client_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_hook_id_t hook_id =
        net_ebpf_extension_get_hook_id_from_wfp_layer_id(incoming_fixed_values->layerId);
    KIRQL old_irql = PASSIVE_LEVEL;
    ebpf_result_t program_result;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_flow_classify_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    if (filter_context->base.context_deleting) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "net_ebpf_extension_flow_classify_flow_established_classify - Client detach detected.",
            STATUS_INVALID_PARAMETER);
        goto Exit;
    }

    local_flow_context = (net_ebpf_extension_flow_classify_wfp_flow_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_extension_flow_classify_wfp_flow_context_t), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, local_flow_context, "flow_context", result);
    memset(local_flow_context, 0, sizeof(net_ebpf_extension_flow_classify_wfp_flow_context_t));

    // Associate the filter context with the local flow context.
    REFERENCE_FILTER_CONTEXT(&filter_context->base);
    local_flow_context->filter_context = filter_context;

    flow_classify_context = &local_flow_context->context.context;
    _net_ebpf_extension_flow_classify_copy_wfp_connection_fields(
        incoming_fixed_values, incoming_metadata_values, &local_flow_context->context);

    client_compartment_id = filter_context->compartment_id;
    ASSERT(
        (client_compartment_id == UNSPECIFIED_COMPARTMENT_ID) ||
        (client_compartment_id == flow_classify_context->compartment_id));
    if (client_compartment_id != UNSPECIFIED_COMPARTMENT_ID &&
        client_compartment_id != flow_classify_context->compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "The cgroup_flow_classify eBPF program is not interested in this compartmentId",
            flow_classify_context->compartment_id);
        goto Exit;
    }

    local_flow_context->parameters.flow_id = incoming_metadata_values->flowHandle;
    local_flow_context->parameters.layer_id = incoming_fixed_values->layerId;
    local_flow_context->parameters.callout_id = net_ebpf_extension_get_callout_id_for_hook(hook_id);

    program_result = net_ebpf_extension_hook_invoke_programs(flow_classify_context, &filter_context->base, &result);
    if (program_result == EBPF_OBJECT_NOT_FOUND) {
        // No program is attached to this hook.
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_WARNING,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "net_ebpf_extension_flow_classify_flow_established_classify - No attached client.");
        goto Exit;
    } else if (program_result != EBPF_SUCCESS) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
            "net_ebpf_extension_flow_classify_flow_established_classify - Program invocation failed.",
            program_result);
        goto Exit;
    }

    status = FwpsFlowAssociateContext(
        local_flow_context->parameters.flow_id,
        local_flow_context->parameters.layer_id,
        local_flow_context->parameters.callout_id,
        (uint64_t)(uintptr_t)local_flow_context);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY, "FwpsFlowAssociateContext", status);
        goto Exit;
    }

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_FLOW_CLASSIFY,
        "New flow created.",
        local_flow_context->parameters.flow_id);

    KeAcquireSpinLock(&filter_context->lock, &old_irql);
    InsertTailList(&filter_context->flow_context_list.list_head, &local_flow_context->link);
    filter_context->flow_context_list.count++;
    KeReleaseSpinLock(&filter_context->lock, old_irql);
    local_flow_context = NULL;

    classify_output->actionType = (result == 0) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    if (classify_output->actionType == FWP_ACTION_BLOCK) {
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

Exit:
    if (local_flow_context != NULL) {
        if (local_flow_context->filter_context != NULL) {
            DEREFERENCE_FILTER_CONTEXT(&local_flow_context->filter_context->base);
        }
        ExFreePool(local_flow_context);
    }
}

void
net_ebpf_extension_flow_classify_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context)
{
    net_ebpf_extension_flow_classify_wfp_flow_context_t* local_flow_context =
        (net_ebpf_extension_flow_classify_wfp_flow_context_t*)(uintptr_t)flow_context;
    net_ebpf_extension_flow_classify_wfp_filter_context_t* filter_context = NULL;
    bpf_flow_classify_t* flow_classify_context = NULL;
    uint32_t result;
    KIRQL irql = 0;

    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);

    ASSERT(local_flow_context != NULL);
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

    // Invoke eBPF program with connection deleted socket event.
    flow_classify_context = &local_flow_context->context.context;
    flow_classify_context->op = BPF_SOCK_OPS_CONNECTION_DELETED_CB;
    if (net_ebpf_extension_hook_invoke_programs(flow_classify_context, &filter_context->base, &result) !=
        EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    if (filter_context) {
        DEREFERENCE_FILTER_CONTEXT(&filter_context->base);
    }

    if (local_flow_context != NULL) {
        ExFreePool(local_flow_context);
    }
}

static ebpf_result_t
_ebpf_flow_classify_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t result;
    bpf_flow_classify_t* flow_classify_context = NULL;
    net_ebpf_flow_classify_t* context_header = NULL;

    *context = NULL;

    // This provider doesn't support data.
    if (data_in != NULL || data_size_in != 0) {
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
