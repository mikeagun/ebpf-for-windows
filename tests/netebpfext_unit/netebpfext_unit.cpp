// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "bpf_helpers.h"
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_nethooks.h"
#include "netebpf_ext_helper.h"
#include "watchdog.h"

#include <map>
#include <stop_token>
#include <thread>

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

#define CONCURRENT_THREAD_RUN_TIME_IN_SECONDS 10

typedef enum _sock_addr_test_type
{
    SOCK_ADDR_TEST_TYPE_CONNECT,
    SOCK_ADDR_TEST_TYPE_RECV_ACCEPT
} sock_addr_test_type_t;

typedef enum _sock_addr_test_action
{
    SOCK_ADDR_TEST_ACTION_PERMIT,
    SOCK_ADDR_TEST_ACTION_BLOCK,
    SOCK_ADDR_TEST_ACTION_REDIRECT,
    SOCK_ADDR_TEST_ACTION_FAILURE,
    SOCK_ADDR_TEST_ACTION_ROUND_ROBIN
} sock_addr_test_action_t;

typedef enum _xdp_test_action
{
    XDP_TEST_ACTION_PASS,   ///< Allow the packet to pass.
    XDP_TEST_ACTION_DROP,   ///< Drop the packet.
    XDP_TEST_ACTION_TX,     ///< Bounce the received packet back out the same NIC it arrived on.
    XDP_TEST_ACTION_FAILURE ///< Failed to invoke the eBPF program.
} xdp_test_action_t;

typedef enum _flow_classify_test_action
{
    FLOW_CLASSIFY_TEST_ACTION_PERMIT,
    FLOW_CLASSIFY_TEST_ACTION_BLOCK,
    FLOW_CLASSIFY_TEST_ACTION_NEED_MORE_DATA
} flow_classify_test_action_t;

TEST_CASE("query program info", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    std::vector<GUID> expected_guids = {
        EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
        EBPF_PROGRAM_TYPE_SOCK_OPS,
        EBPF_PROGRAM_TYPE_FLOW_CLASSIFY,
        EBPF_PROGRAM_TYPE_BIND,
        EBPF_PROGRAM_TYPE_XDP_TEST};
    std::vector<std::string> expected_program_names = {"sock_addr", "sockops", "flow_classify", "bind", "xdp_test"};

    auto guid_less = [](const GUID& lhs, const GUID& rhs) { return memcmp(&lhs, &rhs, sizeof(lhs)) < 0; };

    // Get list of program info providers (attach points and helper functions).
    std::vector<GUID> guids = helper.program_info_provider_guids();

    // Make sure they match.
    std::sort(expected_guids.begin(), expected_guids.end(), guid_less);
    std::sort(guids.begin(), guids.end(), guid_less);
    REQUIRE(guids == expected_guids);

    // Get the names of the program types.
    std::vector<std::string> program_names;
    for (const auto& guid : guids) {
        auto& program_data = *helper.get_program_info_provider_data(guid);
        program_names.push_back(program_data.program_info->program_type_descriptor->name);
    }

    // Make sure they match.
    std::sort(expected_program_names.begin(), expected_program_names.end());
    std::sort(program_names.begin(), program_names.end());
    REQUIRE(expected_program_names == program_names);
}

#pragma region xdp

typedef struct _test_xdp_client_context
{
    netebpfext_helper_base_client_context_t base;
    void* provider_binding_context;
    xdp_test_action_t xdp_action;
} test_xdp_client_context_t;

typedef struct _test_xdp_client_context_header
{
    EBPF_CONTEXT_HEADER;
    test_xdp_client_context_t context;
} test_xdp_client_context_header_t;

// This callback occurs when netebpfext gets a packet and submits it to our dummy
// eBPF program to handle.
_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_xdp_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    ebpf_result_t return_result = EBPF_SUCCESS;
    auto client_context = (test_xdp_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(context);

    switch (client_context->xdp_action) {
    case XDP_TEST_ACTION_PASS:
        *result = XDP_PASS;
        break;
    case XDP_TEST_ACTION_DROP:
        *result = XDP_DROP;
        break;
    case XDP_TEST_ACTION_TX:
        *result = XDP_TX;
        break;
    case XDP_TEST_ACTION_FAILURE:
        return_result = EBPF_FAILED;
        break;
    default:
        *result = XDP_DROP;
        break;
    }

    return return_result;
}

TEST_CASE("classify_packet", "[netebpfext]")
{
    NET_IFINDEX if_index = 0;
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
        .data = &if_index,
        .data_size = sizeof(if_index),
    };
    test_xdp_client_context_header_t client_context_header = {0};
    test_xdp_client_context_t* client_context = &client_context_header.context;
    client_context->base.desired_attach_type = BPF_XDP_TEST;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_xdp_program,
        (netebpfext_helper_base_client_context_t*)client_context);

    // Classify an inbound packet that should pass.
    client_context->xdp_action = XDP_TEST_ACTION_PASS;
    FWP_ACTION_TYPE result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify an inbound packet that should be hairpinned.
    client_context->xdp_action = XDP_TEST_ACTION_TX;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Classify an inbound packet that should be dropped.
    client_context->xdp_action = XDP_TEST_ACTION_DROP;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Classify an inbound packet when eBPF program invocation failed.
    client_context->xdp_action = XDP_TEST_ACTION_FAILURE;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_BLOCK);
}

TEST_CASE("xdp_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto xdp_program_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_XDP_TEST);
    REQUIRE(xdp_program_data != nullptr);

    std::vector<uint8_t> input_data(100);
    std::vector<uint8_t> output_data(100);
    size_t output_data_size = output_data.size();
    xdp_md_t input_context = {};
    size_t output_context_size = sizeof(xdp_md_t);
    xdp_md_t output_context = {};
    xdp_md_t* xdp_context = nullptr;

    input_context.data_meta = 12345;
    input_context.ingress_ifindex = 67890;

    // Negative test:
    // Null data
    REQUIRE(
        xdp_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&xdp_context) ==
        EBPF_INVALID_ARGUMENT);

    // Positive test:
    // Null context
    xdp_context = nullptr;
    REQUIRE(
        xdp_program_data->context_create(input_data.data(), input_data.size(), nullptr, 0, (void**)&xdp_context) ==
        EBPF_SUCCESS);

    xdp_program_data->context_destroy(xdp_context, nullptr, &output_data_size, nullptr, &output_context_size);

    REQUIRE(
        xdp_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&xdp_context) == 0);

    bpf_xdp_adjust_head_t adjust_head =
        reinterpret_cast<bpf_xdp_adjust_head_t>(xdp_program_data->program_type_specific_helper_function_addresses
                                                    ->helper_function_address[XDP_TEST_HELPER_ADJUST_HEAD]);

    // Modify the context.
    REQUIRE(adjust_head(xdp_context, 10) == 0);
    xdp_context->data_meta++;
    xdp_context->ingress_ifindex--;

    output_data_size = output_data.size();

    xdp_program_data->context_destroy(
        xdp_context, output_data.data(), &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == 90);
    REQUIRE(output_context.data_meta == 12346);
    REQUIRE(output_context.ingress_ifindex == 67889);
}

#pragma endregion xdp
#pragma region bind

typedef struct test_bind_client_context_t
{
    netebpfext_helper_base_client_context_t base;
    bind_action_t bind_action;
} test_bind_client_context_t;

typedef struct test_bind_client_context_header_t
{
    EBPF_CONTEXT_HEADER;
    test_bind_client_context_t context;
} test_bind_client_context_header_t;

_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_bind_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    auto client_context = (test_bind_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(context);
    *result = client_context->bind_action;
    return EBPF_SUCCESS;
}

TEST_CASE("bind_invoke", "[netebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_bind_client_context_header_t client_context_header = {0};
    test_bind_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_bind_program,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Classify a bind that should be allowed.
    client_context->bind_action = BIND_PERMIT;
    FWP_ACTION_TYPE result = helper.test_bind_ipv4(&parameters); // TODO(issue #526): support IPv6.
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify a bind that should be redirected.
    client_context->bind_action = BIND_REDIRECT;
    result = helper.test_bind_ipv4(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify a bind that should be blocked.
    client_context->bind_action = BIND_DENY;
    result = helper.test_bind_ipv4(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);
}

TEST_CASE("bind_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto bind_program_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_BIND);
    REQUIRE(bind_program_data != nullptr);

    std::vector<uint8_t> input_data(100);
    std::vector<uint8_t> output_data(100);
    size_t output_data_size = output_data.size();
    bind_md_t input_context = {
        .app_id_start = nullptr,
        .app_id_end = nullptr,
        .process_id = 12345,
        .socket_address = {0x1, 0x2, 0x3, 0x4},
        .socket_address_length = 4,
        .operation = BIND_OPERATION_BIND,
        .protocol = IPPROTO_TCP,
    };
    size_t output_context_size = sizeof(bind_md_t);
    bind_md_t output_context = {};
    bind_md_t* bind_context = nullptr;

    // Positive test:
    // Null data
    REQUIRE(
        bind_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&bind_context) == EBPF_SUCCESS);
    REQUIRE(bind_context->app_id_start <= bind_context->app_id_end);
    bind_program_data->context_destroy(bind_context, nullptr, &output_data_size, nullptr, &output_context_size);

    // Positive test:
    // Valid app id
    wchar_t valid_app_id_1[] = L"TestAppId.exe";
    REQUIRE(
        bind_program_data->context_create(
            (uint8_t*)valid_app_id_1,
            sizeof(valid_app_id_1),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&bind_context) == EBPF_SUCCESS);
    REQUIRE(bind_context->app_id_start <= bind_context->app_id_end);
    REQUIRE(wcscmp((wchar_t*)bind_context->app_id_start, valid_app_id_1) == 0);
    bind_program_data->context_destroy(bind_context, nullptr, &output_data_size, nullptr, &output_context_size);

    // Positive test:
    // Valid app id with full path (truncation logic is used)
    wchar_t valid_app_id_2[] = L"C:\\Windows\\System32\\TestAppId.exe";
    wchar_t truncated_app_id_2[] = L"TestAppId.exe";
    REQUIRE(
        bind_program_data->context_create(
            (uint8_t*)valid_app_id_2,
            sizeof(valid_app_id_2),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&bind_context) == EBPF_SUCCESS);
    REQUIRE(bind_context->app_id_start <= bind_context->app_id_end);
    REQUIRE(wcscmp((wchar_t*)bind_context->app_id_start, truncated_app_id_2) == 0);
    bind_program_data->context_destroy(bind_context, nullptr, &output_data_size, nullptr, &output_context_size);

    // Positive test:
    // Valid app id - only the \ character
    // The WFP framework should not pass the eBPF framework this data, but we should ensure it's handled gracefully.
    wchar_t valid_app_id_3[] = L"\\";
    wchar_t truncated_app_id_3[] = L"";
    REQUIRE(
        bind_program_data->context_create(
            (uint8_t*)valid_app_id_3,
            sizeof(valid_app_id_3),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&bind_context) == EBPF_SUCCESS);
    REQUIRE(bind_context->app_id_start <= bind_context->app_id_end);
    REQUIRE(wcscmp((wchar_t*)bind_context->app_id_start, truncated_app_id_3) == 0);
    bind_program_data->context_destroy(bind_context, nullptr, &output_data_size, nullptr, &output_context_size);

    // Negative test:
    // Null context
    REQUIRE(
        bind_program_data->context_create(input_data.data(), input_data.size(), nullptr, 0, (void**)&bind_context) ==
        EBPF_INVALID_ARGUMENT);
    bind_context = nullptr;

    // Negative test:
    // Odd number of bytes
    byte odd_input_data[5] = {0};
    REQUIRE(
        bind_program_data->context_create(
            odd_input_data,
            sizeof(odd_input_data),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&bind_context) == EBPF_INVALID_ARGUMENT);

    // Negative test:
    // Invalid data size
    REQUIRE(
        bind_program_data->context_create(
            nullptr,
            sizeof(valid_app_id_1),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&bind_context) == EBPF_INVALID_ARGUMENT);

    REQUIRE(
        bind_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&bind_context) == EBPF_SUCCESS);

    // Modify the context.
    bind_context->process_id++;
    bind_context->socket_address[0] = 0x5;
    bind_context->socket_address[1] = 0x6;
    bind_context->socket_address[2] = 0x7;
    bind_context->socket_address[3] = 0x8;
    bind_context->socket_address_length = 8;
    bind_context->operation = BIND_OPERATION_UNBIND;
    bind_context->protocol = IPPROTO_UDP;

    output_context_size = sizeof(bind_md_t);
    output_data_size = output_data.size();

    bind_program_data->context_destroy(
        bind_context, output_data.data(), &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == input_data.size());
    REQUIRE(output_context_size == sizeof(bind_md_t));
    REQUIRE(output_context.app_id_start == nullptr);
    REQUIRE(output_context.app_id_end == nullptr);
    REQUIRE(output_context.process_id == 12346);
    REQUIRE(output_context.socket_address[0] == 0x5);
    REQUIRE(output_context.socket_address[1] == 0x6);
    REQUIRE(output_context.socket_address[2] == 0x7);
    REQUIRE(output_context.socket_address[3] == 0x8);
    REQUIRE(output_context.socket_address_length == 8);
    REQUIRE(output_context.operation == BIND_OPERATION_UNBIND);
    REQUIRE(output_context.protocol == IPPROTO_UDP);
}

#pragma endregion bind
#pragma region cgroup_sock_addr

typedef struct test_sock_addr_client_context_t
{
    netebpfext_helper_base_client_context_t base;
    int sock_addr_action;
    bool validate_sock_addr_entries = true;
} test_sock_addr_client_context_t;

typedef struct test_sock_addr_client_context_header_t
{
    EBPF_CONTEXT_HEADER;
    test_sock_addr_client_context_t context;
} test_sock_addr_client_context_header_t;

static inline sock_addr_test_action_t
_get_sock_addr_action(uint16_t destination_port)
{
    return (sock_addr_test_action_t)(destination_port % SOCK_ADDR_TEST_ACTION_ROUND_ROBIN);
}

static inline FWP_ACTION_TYPE
_get_fwp_sock_addr_action(uint16_t destination_port)
{
    sock_addr_test_action_t action = _get_sock_addr_action(destination_port);
    if (action == SOCK_ADDR_TEST_ACTION_PERMIT || action == SOCK_ADDR_TEST_ACTION_REDIRECT) {
        return FWP_ACTION_PERMIT;
    }

    return FWP_ACTION_BLOCK;
}

_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_sock_addr_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    ebpf_result_t return_result = EBPF_SUCCESS;
    auto client_context = (test_sock_addr_client_context_t*)client_binding_context;
    auto sock_addr_context = (bpf_sock_addr_t*)context;
    int action = SOCK_ADDR_TEST_ACTION_BLOCK;
    int32_t is_admin = 0;

    auto sock_addr_program_data =
        client_context->base.helper->get_program_info_provider_data(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR);

    // Test _ebpf_sock_addr_is_current_admin global helper function.
    // If the user is not admin, then the default action is to block.
    bpf_is_current_admin_t is_current_admin = reinterpret_cast<bpf_is_current_admin_t>(
        sock_addr_program_data->global_helper_function_addresses
            ->helper_function_address[SOCK_ADDR_GLOBAL_HELPER_IS_CURRENT_ADMIN]);
    is_admin = is_current_admin(sock_addr_context);

    // Verify context fields match what the netebpfext helper set.
    // Note that the helper sets the first four bytes of the address to the
    // same value regardless of whether it is IPv4 or IPv6, so we just look
    // at the first four bytes as if it were an IPv4 address.
    if (client_context->validate_sock_addr_entries) {
        REQUIRE((sock_addr_context->family == AF_INET || sock_addr_context->family == AF_INET6));
        REQUIRE(sock_addr_context->user_ip4 == htonl(0x01020304));
        REQUIRE(sock_addr_context->msg_src_ip4 == htonl(0x05060708));
        REQUIRE(sock_addr_context->protocol == IPPROTO_TCP);
        REQUIRE(sock_addr_context->user_port == htons(1234));
        REQUIRE(sock_addr_context->msg_src_port == htons(5678));
    } else {
        ASSERT((sock_addr_context->family == AF_INET || sock_addr_context->family == AF_INET6));
        ASSERT(sock_addr_context->user_ip4 == htonl(0x01020304));
        ASSERT(sock_addr_context->msg_src_ip4 == htonl(0x05060708));
        ASSERT(sock_addr_context->protocol == IPPROTO_TCP);
        ASSERT(sock_addr_context->user_port == htons(1234));
        ASSERT(sock_addr_context->msg_src_port == htons(5678));
    }

    if (is_admin) {
        // If the action is round robin, decide the action based on the port number.
        if (client_context->sock_addr_action == SOCK_ADDR_TEST_ACTION_ROUND_ROBIN) {
            action = _get_sock_addr_action(sock_addr_context->user_port);
        } else {
            action = client_context->sock_addr_action;
        }
    }

    switch (action) {
    case SOCK_ADDR_TEST_ACTION_PERMIT:
        *result = BPF_SOCK_ADDR_VERDICT_PROCEED;
        break;
    case SOCK_ADDR_TEST_ACTION_BLOCK:
        *result = BPF_SOCK_ADDR_VERDICT_REJECT;
        break;
    case SOCK_ADDR_TEST_ACTION_REDIRECT:
        sock_addr_context->user_port++;
        if (sock_addr_context->family == AF_INET) {
            sock_addr_context->user_ip4++;
        } else {
            auto first_octet = &sock_addr_context->user_ip6[0];
            (*first_octet)++;
        }
        *result = BPF_SOCK_ADDR_VERDICT_PROCEED;
        break;
    case SOCK_ADDR_TEST_ACTION_FAILURE:
        return_result = EBPF_FAILED;
        break;
    default:
        *result = BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return return_result;
}

TEST_CASE("sock_addr_invoke", "[netebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_sock_addr_client_context_header_t client_context_header = {0};
    test_sock_addr_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Classify operations that should be allowed.
    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_PERMIT;
    client_context->validate_sock_addr_entries = true;

    FWP_ACTION_TYPE result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify operations that should be blocked.
    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_BLOCK;

    result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Classify operations for redirect.
    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_REDIRECT;

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Test eBPF program invocation failure.
    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_FAILURE;

    result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Test reauthorization flag.
    // Classify operations that should be allowed.
    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_PERMIT;
    client_context->validate_sock_addr_entries = true;

    parameters.reauthorization_flag = FWP_CONDITION_FLAG_IS_REAUTHORIZE;

    result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);
}

void
sock_addr_thread_function(
    std::stop_token token,
    _In_ netebpf_ext_helper_t* helper,
    _In_ fwp_classify_parameters_t* parameters,
    sock_addr_test_type_t type,
    uint16_t start_port,
    uint16_t end_port,
    std::atomic<size_t>* failure_count)
{
    FWP_ACTION_TYPE result;
    uint16_t port_number;

    bool fault_injection_enabled = cxplat_fault_injection_is_enabled();

    if (start_port != end_port) {
        port_number = start_port - 1;
    } else {
        port_number = htons(parameters->destination_port);
    }

    while (!token.stop_requested()) {
        // If start_port and end_port are same, then the port number for each
        // invocation will remain the same.
        if (start_port != end_port) {
            port_number++;
            if (port_number > end_port) {
                port_number = start_port;
            }
            parameters->destination_port = htons(port_number);
        }

        switch (type) {
        case SOCK_ADDR_TEST_TYPE_RECV_ACCEPT:
            result = helper->test_cgroup_inet4_recv_accept(parameters);
            break;
        case SOCK_ADDR_TEST_TYPE_CONNECT:
        default:
            result = helper->test_cgroup_inet4_connect(parameters);
            break;
        }

        auto expected_result = _get_fwp_sock_addr_action(port_number);
        if (result != expected_result) {
            if (fault_injection_enabled) {
                // If fault injection is enabled, then the result can be different.
                continue;
            }

            (*failure_count)++;
            break;
        }
    }
}

// Invoke SOCK_ADDR_CONNECT concurrently with same classify parameters.

TEST_CASE("sock_addr_invoke_concurrent1", "[netebpfext_concurrent]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_sock_addr_client_context_header_t client_context_header = {0};
    test_sock_addr_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};
    std::vector<std::jthread> threads;
    std::atomic<size_t> failure_count = 0;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);
    client_context->validate_sock_addr_entries = false;

    // Classify operations that should be allowed.
    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_PERMIT;

    uint32_t thread_count = 2 * ebpf_get_cpu_count();
    for (uint32_t i = 0; i < thread_count; i++) {
        threads.emplace_back(
            sock_addr_thread_function,
            &helper,
            &parameters,
            SOCK_ADDR_TEST_TYPE_CONNECT,
            parameters.destination_port,
            parameters.destination_port,
            &failure_count);
    }

    // Wait for 10 seconds.
    std::this_thread::sleep_for(std::chrono::seconds(CONCURRENT_THREAD_RUN_TIME_IN_SECONDS));

    // Stop all threads.
    for (auto& thread : threads) {
        thread.request_stop();
    }

    // Wait for all threads to stop.
    for (auto& thread : threads) {
        thread.join();
    }

    REQUIRE(failure_count == 0);
}

// Invoke SOCK_ADDR_CONNECT concurrently with different classify parameters.
TEST_CASE("sock_addr_invoke_concurrent2", "[netebpfext_concurrent]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_sock_addr_client_context_header_t client_context_header = {0};
    test_sock_addr_client_context_t* client_context = &client_context_header.context;
    std::vector<std::jthread> threads;
    std::vector<fwp_classify_parameters_t> parameters;
    std::atomic<size_t> failure_count = 0;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)client_context);

    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_ROUND_ROBIN;
    client_context->validate_sock_addr_entries = false;

    uint32_t thread_count = 2 * ebpf_get_cpu_count();
    parameters.resize(thread_count);

    for (uint32_t i = 0; i < thread_count; i++) {
        netebpfext_initialize_fwp_classify_parameters(&parameters[i]);
        threads.emplace_back(
            sock_addr_thread_function,
            &helper,
            &parameters[i],
            SOCK_ADDR_TEST_TYPE_CONNECT,
            (uint16_t)(i * 1000),
            (uint16_t)(i * 1000 + 1000),
            &failure_count);
    }

    // Wait for 10 seconds.
    std::this_thread::sleep_for(std::chrono::seconds(CONCURRENT_THREAD_RUN_TIME_IN_SECONDS));

    // Stop all threads.
    for (auto& thread : threads) {
        thread.request_stop();
    }

    // Wait for all threads to stop.
    for (auto& thread : threads) {
        thread.join();
    }

    REQUIRE(failure_count == 0);
}

// Invoke SOCK_ADDR_RECV_ACCEPT concurrently with different classify parameters.
TEST_CASE("sock_addr_invoke_concurrent3", "[netebpfext_concurrent]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_sock_addr_client_context_header_t client_context_header = {0};
    test_sock_addr_client_context_t* client_context = &client_context_header.context;
    std::vector<std::jthread> threads;
    std::vector<fwp_classify_parameters_t> parameters;
    std::atomic<size_t> failure_count = 0;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)client_context);

    client_context->sock_addr_action = SOCK_ADDR_TEST_ACTION_ROUND_ROBIN;
    client_context->validate_sock_addr_entries = false;

    uint32_t thread_count = 2 * ebpf_get_cpu_count();
    parameters.resize(thread_count);

    for (uint32_t i = 0; i < thread_count; i++) {
        netebpfext_initialize_fwp_classify_parameters(&parameters[i]);
        threads.emplace_back(
            sock_addr_thread_function,
            &helper,
            &parameters[i],
            SOCK_ADDR_TEST_TYPE_RECV_ACCEPT,
            (uint16_t)(i * 1000),
            (uint16_t)(i * 1000 + 1000),
            &failure_count);
    }

    // Wait for 10 seconds.
    std::this_thread::sleep_for(std::chrono::seconds(CONCURRENT_THREAD_RUN_TIME_IN_SECONDS));

    // Stop all threads.
    for (auto& thread : threads) {
        thread.request_stop();
    }

    // Wait for all threads to stop.
    for (auto& thread : threads) {
        thread.join();
    }

    REQUIRE(failure_count == 0);
}

TEST_CASE("sock_addr_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto sock_addr_program_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR);
    REQUIRE(sock_addr_program_data != nullptr);

    size_t output_data_size = 0;
    bpf_sock_addr_t input_context = {
        AF_INET,
        0x12345678,
        0x1234,
        0x90abcdef,
        0x5678,
        IPPROTO_TCP,
        0x12345678,
        0x1234567890abcdef,
    };
    size_t output_context_size = sizeof(bpf_sock_addr_t);
    bpf_sock_addr_t output_context = {};
    bpf_sock_addr_t* sock_addr_context = nullptr;

    std::vector<uint8_t> input_data(100);

    // Negative test:
    // Data present
    REQUIRE(
        sock_addr_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&sock_addr_context) == EBPF_INVALID_ARGUMENT);
    sock_addr_context = nullptr;

    // Negative test:
    // Context missing
    REQUIRE(
        sock_addr_program_data->context_create(nullptr, 0, nullptr, 0, (void**)&sock_addr_context) ==
        EBPF_INVALID_ARGUMENT);
    sock_addr_context = nullptr;

    REQUIRE(
        sock_addr_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&sock_addr_context) == 0);

    // Modify the context.
    sock_addr_context->family = AF_INET6;
    sock_addr_context->msg_src_ip4++;
    sock_addr_context->msg_src_port--;
    sock_addr_context->user_ip4++;
    sock_addr_context->user_port--;
    sock_addr_context->protocol = IPPROTO_UDP;
    sock_addr_context->compartment_id++;
    sock_addr_context->interface_luid--;

    sock_addr_program_data->context_destroy(
        sock_addr_context, nullptr, &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == 0);
    REQUIRE(output_context_size == sizeof(bpf_sock_addr_t));
    REQUIRE(output_context.family == AF_INET6);
    REQUIRE(output_context.msg_src_ip4 == 0x12345679);
    REQUIRE(output_context.msg_src_port == 0x1233);
    REQUIRE(output_context.user_ip4 == 0x90abcdf0);
    REQUIRE(output_context.user_port == 0x5677);
    REQUIRE(output_context.protocol == IPPROTO_UDP);
    REQUIRE(output_context.compartment_id == 0x12345679);
    REQUIRE(output_context.interface_luid == 0x1234567890abcdee);
}
#pragma endregion cgroup_sock_addr
#pragma region sock_ops

typedef struct test_sock_ops_client_context_t
{
    netebpfext_helper_base_client_context_t base;
    uint32_t sock_ops_action;
} test_sock_ops_client_context_t;

typedef struct test_sock_ops_client_context_header_t
{
    EBPF_CONTEXT_HEADER;
    test_sock_ops_client_context_t context;
} test_sock_ops_client_context_header_t;

_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_sock_ops_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    auto client_context = (test_sock_ops_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(context);
    *result = client_context->sock_ops_action;
    return EBPF_SUCCESS;
}

TEST_CASE("sock_ops_invoke", "[netebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_sock_ops_client_context_header_t client_context_header = {0};
    test_sock_ops_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_ops_program,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Do some operations that return success.
    client_context->sock_ops_action = 0;

    FWP_ACTION_TYPE result = helper.test_sock_ops_v4(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_sock_ops_v6(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Do some operations that return failure.
    client_context->sock_ops_action = -1;

    result = helper.test_sock_ops_v4(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_sock_ops_v6(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);
}

TEST_CASE("sock_ops_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto sock_ops_program_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_SOCK_OPS);
    REQUIRE(sock_ops_program_data != nullptr);

    size_t output_data_size = 0;
    bpf_sock_ops_t input_context = {
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        AF_INET,
        0x12345678,
        0x1234,
        0x90abcdef,
        0x5678,
        IPPROTO_TCP,
        0x12345678,
        0x1234567890abcdef,
    };
    size_t output_context_size = sizeof(bpf_sock_ops_t);
    bpf_sock_ops_t output_context = {};
    bpf_sock_ops_t* sock_ops_context = nullptr;

    std::vector<uint8_t> input_data(100);

    // Negative test:
    // Data present
    REQUIRE(
        sock_ops_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&sock_ops_context) == EBPF_INVALID_ARGUMENT);

    // Negative test:
    // Context missing
    REQUIRE(
        sock_ops_program_data->context_create(nullptr, 0, nullptr, 0, (void**)&sock_ops_context) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        sock_ops_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&sock_ops_context) == 0);

    // Modify the context.
    sock_ops_context->op = BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
    sock_ops_context->family = AF_INET6;
    sock_ops_context->local_ip4++;
    sock_ops_context->local_port--;
    sock_ops_context->remote_ip4++;
    sock_ops_context->remote_port--;
    sock_ops_context->protocol = IPPROTO_UDP;
    sock_ops_context->compartment_id++;
    sock_ops_context->interface_luid--;

    sock_ops_program_data->context_destroy(
        sock_ops_context, nullptr, &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == 0);
    REQUIRE(output_context_size == sizeof(bpf_sock_ops_t));
    REQUIRE(output_context.op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB);
    REQUIRE(output_context.family == AF_INET6);
    REQUIRE(output_context.local_ip4 == 0x12345679);
    REQUIRE(output_context.local_port == 0x1233);
    REQUIRE(output_context.remote_ip4 == 0x90abcdf0);
    REQUIRE(output_context.remote_port == 0x5677);
    REQUIRE(output_context.protocol == IPPROTO_UDP);
    REQUIRE(output_context.compartment_id == 0x12345679);
    REQUIRE(output_context.interface_luid == 0x1234567890abcdee);
}
#pragma endregion sock_ops

#pragma region flow_classify

typedef struct test_flow_classify_client_context_t
{
    netebpfext_helper_base_client_context_t base;
    flow_classify_test_action_t flow_classify_action;
    uint32_t flow_established_count;
    uint32_t flow_classify_count;
    bool validate_flow_context;
    uint64_t expected_flow_id;
    bool expect_flow_established; // true for ALE, false for flow classify
} test_flow_classify_client_context_t;

typedef struct test_flow_classify_client_context_header_t
{
    EBPF_CONTEXT_HEADER;
    test_flow_classify_client_context_t context;
} test_flow_classify_client_context_header_t;

_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_flow_callback(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    auto client_context = (test_flow_classify_client_context_t*)client_binding_context;
    auto flow_context = (bpf_flow_classify_t*)context;

    if (client_context->expect_flow_established) {
        // ALE (flow established) callback
        client_context->flow_established_count++;
        if (client_context->validate_flow_context && flow_context != nullptr) {
            if (flow_context->family != AF_INET && flow_context->family != AF_INET6) {
                return EBPF_INVALID_ARGUMENT;
            }
            if (client_context->expected_flow_id != 0 && flow_context->flow_id != client_context->expected_flow_id) {
                return EBPF_INVALID_ARGUMENT;
            }
        }
        *result = FWP_ACTION_PERMIT;
        return EBPF_SUCCESS;
    } else {
        // Flow classify callback
        client_context->flow_classify_count++;
        if (client_context->validate_flow_context && flow_context != nullptr) {
            if (flow_context->family != AF_INET && flow_context->family != AF_INET6) {
                return EBPF_INVALID_ARGUMENT;
            }
            if (client_context->expected_flow_id != 0 && flow_context->flow_id != client_context->expected_flow_id) {
                return EBPF_INVALID_ARGUMENT;
            }
        }
        switch (client_context->flow_classify_action) {
        case FLOW_CLASSIFY_TEST_ACTION_PERMIT:
            *result = FWP_ACTION_PERMIT;
            break;
        case FLOW_CLASSIFY_TEST_ACTION_BLOCK:
            *result = FWP_ACTION_BLOCK;
            break;
        case FLOW_CLASSIFY_TEST_ACTION_NEED_MORE_DATA:
            *result = FWP_ACTION_CONTINUE;
            break;
        default:
            *result = FWP_ACTION_PERMIT;
            break;
        }
        return EBPF_SUCCESS;
    }
}

TEST_CASE("flow_classify_provider_registration", "[flow_classify]")
{
    netebpf_ext_helper_t helper;

    // Verify that FLOW_CLASSIFY program type is registered
    auto flow_classify_program_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_FLOW_CLASSIFY);
    REQUIRE(flow_classify_program_data != nullptr);

    // Verify basic program data structure
    REQUIRE(flow_classify_program_data->program_info != nullptr);
    REQUIRE(flow_classify_program_data->context_create != nullptr);
    REQUIRE(flow_classify_program_data->context_destroy != nullptr);
    REQUIRE(flow_classify_program_data->required_irql == DISPATCH_LEVEL);
}

TEST_CASE("flow_classify_invoke_ale_v4", "[flow_classify]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Setup IPv4 specific parameters
    parameters.source_ipv4_address = 0xC0A80101;      // 192.168.1.1
    parameters.destination_ipv4_address = 0xC0A80102; // 192.168.1.2
    parameters.source_port = 12345;
    parameters.destination_port = 80;
    parameters.protocol = IPPROTO_TCP;

    // Test FLOW_CLASSIFY_ALLOW action
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;
    client_context->expect_flow_established = true;
    FWP_ACTION_TYPE result = helper.test_flow_classify_ale_v4(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);
    REQUIRE(client_context->flow_established_count == 1);

    // Test FLOW_CLASSIFY_BLOCK action
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_BLOCK;
    client_context->expect_flow_established = false;
    client_context->flow_classify_count = 0; // Reset counter
    result = helper.test_flow_classify_ale_v4(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);
    REQUIRE(client_context->flow_classify_count == 1);

    // Test FLOW_CLASSIFY_NEED_MORE_DATA action
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_NEED_MORE_DATA;
    client_context->flow_classify_count = 0; // Reset counter
    result = helper.test_flow_classify_ale_v4(&parameters);
    REQUIRE(result == FWP_ACTION_CONTINUE);
    REQUIRE(client_context->flow_classify_count == 1);
}

TEST_CASE("flow_classify_invoke_ale_v6", "[flow_classify]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Setup IPv6 specific parameters
    uint8_t source_ipv6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t dest_ipv6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    memcpy(&parameters.source_ipv6_address, source_ipv6, sizeof(source_ipv6));
    memcpy(&parameters.destination_ipv6_address, dest_ipv6, sizeof(dest_ipv6));
    parameters.source_port = 54321;
    parameters.destination_port = 443;
    parameters.protocol = IPPROTO_TCP;

    // Test FLOW_CLASSIFY_ALLOW action
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;
    client_context->expect_flow_established = true;

    FWP_ACTION_TYPE result = helper.test_flow_classify_ale_v6(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);
    REQUIRE(client_context->flow_established_count == 1);

    // Test FLOW_CLASSIFY_BLOCK action
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_BLOCK;
    client_context->expect_flow_established = false;
    client_context->flow_classify_count = 0; // Reset counter

    result = helper.test_flow_classify_ale_v6(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);
    REQUIRE(client_context->flow_classify_count == 1);

    // Test FLOW_CLASSIFY_NEED_MORE_DATA action
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_NEED_MORE_DATA;
    client_context->flow_classify_count = 0; // Reset counter

    result = helper.test_flow_classify_ale_v6(&parameters);
    REQUIRE(result == FWP_ACTION_CONTINUE);
    REQUIRE(client_context->flow_classify_count == 1);
}

TEST_CASE("flow_classify_invoke_stream_v4", "[flow_classify]")
{
    // NOTE: Stream layer tests require prior ALE flow establishment
    // The ALE layer creates the flow context that the stream layer uses

    ebpf_extension_data_t ale_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    ebpf_extension_data_t flow_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };

    fwp_classify_parameters_t parameters = {};

    test_flow_classify_client_context_header_t ale_client_context_header = {0};
    test_flow_classify_client_context_t* ale_client_context = &ale_client_context_header.context;

    test_flow_classify_client_context_header_t flow_client_context_header = {0};
    test_flow_classify_client_context_t* flow_client_context = &flow_client_context_header.context;

    // ALE helper for flow establishment
    netebpf_ext_helper_t ale_helper(
        &ale_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)ale_client_context);

    // Stream helper for data processing
    netebpf_ext_helper_t stream_helper(
        &flow_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)flow_client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Setup IPv4 TCP stream parameters
    parameters.source_ipv4_address = 0x0A000001;      // 10.0.0.1
    parameters.destination_ipv4_address = 0x0A000002; // 10.0.0.2
    parameters.source_port = 8080;
    parameters.destination_port = 3000;
    parameters.protocol = IPPROTO_TCP;

    ale_client_context->validate_flow_context = true;
    flow_client_context->validate_flow_context = true;

    // STEP 1: First establish the flow context through ALE layer
    // This simulates the TCP connection establishment phase
    ale_client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    ale_client_context->validate_flow_context = true;
    ale_client_context->flow_classify_count = 0;

    FWP_ACTION_TYPE ale_result = ale_helper.test_flow_classify_ale_v4(&parameters);
    REQUIRE(ale_result == FWP_ACTION_PERMIT);
    REQUIRE(ale_client_context->flow_classify_count == 1);

    // STEP 2: Now test stream layer with established flow context
    // This simulates TCP data segment processing

    // Test FLOW_CLASSIFY_ALLOW action on stream layer
    flow_client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    flow_client_context->flow_classify_count = 0; // Reset counter

    flow_classify_action_t result =
        static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v4(&parameters));
    REQUIRE(result == FLOW_CLASSIFY_ALLOW);
    REQUIRE(flow_client_context->flow_classify_count == 1);

    // Test FLOW_CLASSIFY_BLOCK action on stream layer
    flow_client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_BLOCK;
    flow_client_context->flow_classify_count = 0; // Reset counter

    result = static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v4(&parameters));
    REQUIRE(result == FLOW_CLASSIFY_BLOCK);
    REQUIRE(flow_client_context->flow_classify_count == 1);

    // Test FLOW_CLASSIFY_NEED_MORE_DATA action on stream layer
    flow_client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_NEED_MORE_DATA;
    flow_client_context->flow_classify_count = 0; // Reset counter

    result = static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v4(&parameters));
    REQUIRE(result == FLOW_CLASSIFY_ALLOW);
    REQUIRE(flow_client_context->flow_classify_count == 1);
}

TEST_CASE("flow_classify_invoke_stream_v6", "[flow_classify]")
{
    // NOTE: Stream layer tests require prior ALE flow establishment
    // The ALE layer creates the flow context that the stream layer uses

    ebpf_extension_data_t ale_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };

    ebpf_extension_data_t flow_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    // ALE helper for flow establishment
    netebpf_ext_helper_t ale_helper(
        &ale_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    // Stream helper for data processing
    netebpf_ext_helper_t stream_helper(
        &flow_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Setup IPv6 TCP stream parameters
    uint8_t source_ipv6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t dest_ipv6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    memcpy(&parameters.source_ipv6_address, source_ipv6, sizeof(source_ipv6));
    memcpy(&parameters.destination_ipv6_address, dest_ipv6, sizeof(dest_ipv6));
    parameters.source_port = 9000;
    parameters.destination_port = 5000;
    parameters.protocol = IPPROTO_TCP;

    // STEP 1: First establish the flow context through ALE layer
    // This simulates the TCP connection establishment phase
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;
    client_context->flow_classify_count = 0;

    FWP_ACTION_TYPE ale_result = ale_helper.test_flow_classify_ale_v6(&parameters);
    REQUIRE(ale_result == FWP_ACTION_PERMIT);
    REQUIRE(client_context->flow_classify_count == 1);

    // STEP 2: Now test stream layer with established flow context
    // This simulates TCP data segment processing

    // Test FLOW_CLASSIFY_ALLOW action on stream layer
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;
    client_context->flow_classify_count = 0; // Reset counter

    flow_classify_action_t result =
        static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v6(&parameters));
    REQUIRE(result == FLOW_CLASSIFY_ALLOW);
    REQUIRE(client_context->flow_classify_count == 1);

    // Test FLOW_CLASSIFY_BLOCK action on stream layer
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_BLOCK;
    client_context->flow_classify_count = 0; // Reset counter

    result = static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v6(&parameters));
    REQUIRE(result == FLOW_CLASSIFY_BLOCK);
    REQUIRE(client_context->flow_classify_count == 1);

    // Test FLOW_CLASSIFY_NEED_MORE_DATA action on stream layer
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_NEED_MORE_DATA;
    client_context->flow_classify_count = 0; // Reset counter

    result = static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v6(&parameters));
    REQUIRE(result == FLOW_CLASSIFY_ALLOW);
    REQUIRE(client_context->flow_classify_count == 1);
}

TEST_CASE("flow_classify_lifecycle_simulation", "[flow_classify]")
{
    ebpf_extension_data_t ale_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    ebpf_extension_data_t flow_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    // ALE helper for flow establishment
    netebpf_ext_helper_t ale_helper(
        &ale_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    // Stream helper for data processing
    netebpf_ext_helper_t stream_helper(
        &flow_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Setup flow parameters for a complete flow lifecycle test
    parameters.source_ipv4_address = 0xAC100001;      // 172.16.0.1
    parameters.destination_ipv4_address = 0xAC100002; // 172.16.0.2
    parameters.source_port = 40000;
    parameters.destination_port = 22; // SSH
    parameters.protocol = IPPROTO_TCP;

    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;

    // Simulate complete flow lifecycle:
    // 1. Flow established at ALE layer (sets up flow context)
    FWP_ACTION_TYPE result = ale_helper.test_flow_classify_ale_v4(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);
    uint32_t ale_calls = client_context->flow_classify_count;
    REQUIRE(ale_calls >= 1);

    // 2. Multiple stream classifications (processes data segments)
    client_context->flow_classify_count = 0; // Reset to count only stream calls
    for (int i = 0; i < 5; i++) {
        result = static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v4(&parameters));
        REQUIRE(result == FLOW_CLASSIFY_ALLOW);
    }
    REQUIRE(client_context->flow_classify_count == 5);

    // 3. Test blocking mid-flow
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_BLOCK;
    result = static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v4(&parameters));
    REQUIRE(result == FLOW_CLASSIFY_BLOCK);

    // Note: Flow deletion is handled automatically by WFP when flow ends
    // In a real scenario, net_ebpf_extension_flow_classify_flow_delete would be called
}

TEST_CASE("flow_classify_multiple_flows", "[flow_classify]")
{
    ebpf_extension_data_t ale_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    ebpf_extension_data_t flow_npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;

    // ALE helper for flow establishment
    netebpf_ext_helper_t ale_helper(
        &ale_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    // Stream helper for data processing
    netebpf_ext_helper_t stream_helper(
        &flow_npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;

    // Test multiple concurrent flows with different parameters
    std::vector<fwp_classify_parameters_t> flows(3);

    // Flow 1: HTTP traffic
    netebpfext_initialize_fwp_classify_parameters(&flows[0]);
    flows[0].source_ipv4_address = 0xC0A80110;      // 192.168.1.16
    flows[0].destination_ipv4_address = 0x08080808; // 8.8.8.8
    flows[0].source_port = 55000;
    flows[0].destination_port = 80;
    flows[0].protocol = IPPROTO_TCP;

    // Flow 2: HTTPS traffic
    netebpfext_initialize_fwp_classify_parameters(&flows[1]);
    flows[1].source_ipv4_address = 0xC0A80111;      // 192.168.1.17
    flows[1].destination_ipv4_address = 0x08080404; // 8.8.4.4
    flows[1].source_port = 55001;
    flows[1].destination_port = 443;
    flows[1].protocol = IPPROTO_TCP;

    // Flow 3: SSH traffic (changed from DNS UDP to SSH TCP since flow_classify is TCP-only)
    netebpfext_initialize_fwp_classify_parameters(&flows[2]);
    flows[2].source_ipv4_address = 0xC0A80112;      // 192.168.1.18
    flows[2].destination_ipv4_address = 0x08080808; // 8.8.8.8
    flows[2].source_port = 55002;
    flows[2].destination_port = 22; // SSH
    flows[2].protocol = IPPROTO_TCP;

    // Test each flow at ALE layer (establish flow contexts)
    for (size_t i = 0; i < flows.size(); i++) {
        client_context->flow_classify_count = 0;
        FWP_ACTION_TYPE result = ale_helper.test_flow_classify_ale_v4(&flows[i]);
        REQUIRE(result == FWP_ACTION_PERMIT);
        REQUIRE(client_context->flow_classify_count >= 1);
    }

    // Test all TCP flows at stream layer (all flows are TCP for flow_classify)
    for (size_t i = 0; i < flows.size(); i++) {
        client_context->flow_classify_count = 0;
        flow_classify_action_t result =
            static_cast<flow_classify_action_t>(stream_helper.test_flow_classify_stream_v4(&flows[i]));
        REQUIRE(result == FLOW_CLASSIFY_ALLOW);
        REQUIRE(client_context->flow_classify_count >= 1);
    }
}

// TODO: sort this -- currently we always allow ale.
// TEST_CASE("flow_classify_error_handling", "[flow_classify]")
//{
//    ebpf_extension_data_t npi_specific_characteristics = {
//        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
//    };
//    test_flow_classify_client_context_header_t client_context_header = {0};
//    test_flow_classify_client_context_t* client_context = &client_context_header.context;
//    fwp_classify_parameters_t parameters = {};
//
//    netebpf_ext_helper_t helper(
//        &npi_specific_characteristics,
//        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
//        (netebpfext_helper_base_client_context_t*)client_context);
//
//    netebpfext_initialize_fwp_classify_parameters(&parameters);
//
//    // Test with invalid flow_classify return values
//    client_context->flow_classify_action = 999; // Invalid action
//    client_context->validate_flow_context = true;
//
//    FWP_ACTION_TYPE result = helper.test_flow_classify_ale_v4(&parameters);
//    // Invalid actions should be treated as BLOCK for security
//    REQUIRE(result == FWP_ACTION_BLOCK);
//
//    // Test program execution failure simulation
//    // Note: In a real scenario, we'd test EBPF_ERROR return from invoke function,
//    // but that would require modifying the invoke function to return errors
//}

TEST_CASE("flow_classify_compartment_filtering", "[flow_classify]")
{
    // Test flow classification with specific compartment ID filtering
    uint32_t test_compartment_id = 12345;
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
        .data = &test_compartment_id,
        .data_size = sizeof(test_compartment_id),
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);
    parameters.compartment_id = test_compartment_id;

    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;

    // Test flow classification with matching compartment ID
    FWP_ACTION_TYPE result = helper.test_flow_classify_ale_v4(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);
    REQUIRE(client_context->flow_classify_count >= 1);
}

TEST_CASE("flow_classify_context", "[flow_classify]")
{
    netebpf_ext_helper_t helper;
    auto flow_classify_program_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_FLOW_CLASSIFY);
    REQUIRE(flow_classify_program_data != nullptr);

    // Test IPv4 context creation and manipulation
    size_t output_data_size = 0;
    bpf_flow_classify_t input_context_v4 = {};
    input_context_v4.family = AF_INET;
    input_context_v4.local_ip4 = 0x12345678;
    input_context_v4.local_port = 0x1234;
    input_context_v4.remote_ip4 = 0x90abcdef;
    input_context_v4.remote_port = 0x5678;
    input_context_v4.protocol = IPPROTO_TCP;
    input_context_v4.compartment_id = 0x12345678;
    input_context_v4.interface_luid = 0x1234567890abcdefULL;
    input_context_v4.direction = static_cast<uint8_t>(1);
    input_context_v4.flow_id = 0x1111222233334444ULL;
    input_context_v4.data_start = nullptr;
    input_context_v4.data_end = nullptr;
    size_t output_context_size = sizeof(bpf_flow_classify_t);
    bpf_flow_classify_t output_context = {};
    bpf_flow_classify_t* flow_classify_context = nullptr;

    std::vector<uint8_t> input_data(100);

    // Positive test: valid context create call.
    REQUIRE(
        flow_classify_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context_v4,
            sizeof(input_context_v4),
            (void**)&flow_classify_context) == EBPF_SUCCESS);

    // Negative test: Context missing (context is required)
    REQUIRE(
        flow_classify_program_data->context_create(nullptr, 0, nullptr, 0, (void**)&flow_classify_context) ==
        EBPF_INVALID_ARGUMENT);

    // Negative test: Data missing (data is required)
    REQUIRE(
        flow_classify_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context_v4, sizeof(input_context_v4), (void**)&flow_classify_context) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(flow_classify_context != nullptr);
    REQUIRE(flow_classify_context->family == AF_INET);
    REQUIRE(flow_classify_context->local_ip4 == 0x12345678);
    REQUIRE(flow_classify_context->local_port == 0x1234);
    REQUIRE(flow_classify_context->remote_ip4 == 0x90abcdef);
    REQUIRE(flow_classify_context->remote_port == 0x5678);
    REQUIRE(flow_classify_context->protocol == IPPROTO_TCP);
    REQUIRE(flow_classify_context->compartment_id == 0x12345678);
    REQUIRE(flow_classify_context->interface_luid == 0x1234567890abcdef);
    REQUIRE(flow_classify_context->direction == 1);
    REQUIRE(flow_classify_context->flow_id == 0x1111222233334444);

    // Modify the context to test changes
    flow_classify_context->family = AF_INET6;
    flow_classify_context->local_ip4++;
    flow_classify_context->local_port--;
    flow_classify_context->remote_ip4++;
    flow_classify_context->remote_port--;
    flow_classify_context->protocol = IPPROTO_UDP;
    flow_classify_context->compartment_id++;
    flow_classify_context->interface_luid--;
    flow_classify_context->direction = 0;
    flow_classify_context->flow_id++;

    flow_classify_program_data->context_destroy(
        flow_classify_context, nullptr, &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == 0);
    REQUIRE(output_context_size == sizeof(bpf_flow_classify_t));
    REQUIRE(output_context.family == AF_INET6);
    REQUIRE(output_context.local_ip4 == 0x12345679);
    REQUIRE(output_context.local_port == 0x1233);
    REQUIRE(output_context.remote_ip4 == 0x90abcdf0);
    REQUIRE(output_context.remote_port == 0x5677);
    REQUIRE(output_context.protocol == IPPROTO_UDP);
    REQUIRE(output_context.compartment_id == 0x12345679);
    REQUIRE(output_context.interface_luid == 0x1234567890abcdee);
    REQUIRE(output_context.direction == 0);
    REQUIRE(output_context.flow_id == 0x1111222233334445);

    // Test IPv6 context
    uint8_t local_ipv6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t remote_ipv6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    bpf_flow_classify_t input_context_v6 = {};
    input_context_v6.family = AF_INET6;
    input_context_v6.local_port = static_cast<uint32_t>(0x1bb);
    input_context_v6.remote_port = static_cast<uint32_t>(0x1bb);
    input_context_v6.protocol = IPPROTO_TCP;
    input_context_v6.compartment_id = 0xabcdef01;
    input_context_v6.interface_luid = 0x9876543210fedcbaULL;
    input_context_v6.direction = static_cast<uint8_t>(0);
    input_context_v6.flow_id = 0x5555aaaa5555aaaaULL;
    input_context_v6.data_start = nullptr;
    input_context_v6.data_end = nullptr;

    // Fill in IPv6 addresses after initialization
    memcpy(input_context_v6.local_ip6, local_ipv6, sizeof(local_ipv6));
    memcpy(input_context_v6.remote_ip6, remote_ipv6, sizeof(remote_ipv6));

    flow_classify_context = nullptr;
    REQUIRE(
        flow_classify_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context_v6, sizeof(input_context_v6), (void**)&flow_classify_context) ==
        0);

    REQUIRE(flow_classify_context != nullptr);
    REQUIRE(flow_classify_context->family == AF_INET6);
    REQUIRE(memcmp(flow_classify_context->local_ip6, local_ipv6, sizeof(local_ipv6)) == 0);
    REQUIRE(memcmp(flow_classify_context->remote_ip6, remote_ipv6, sizeof(remote_ipv6)) == 0);
    REQUIRE(flow_classify_context->local_port == 0x8080);
    REQUIRE(flow_classify_context->remote_port == 0x1bb);
    REQUIRE(flow_classify_context->protocol == IPPROTO_TCP);
    REQUIRE(flow_classify_context->compartment_id == 0xabcdef01);
    REQUIRE(flow_classify_context->interface_luid == 0x9876543210fedcba);
    REQUIRE(flow_classify_context->direction == 0);
    REQUIRE(flow_classify_context->flow_id == 0x5555aaaa5555aaaa);

    // Clean up IPv6 context
    output_context_size = sizeof(bpf_flow_classify_t);
    flow_classify_program_data->context_destroy(
        flow_classify_context, nullptr, &output_data_size, (uint8_t*)&output_context, &output_context_size);
}

TEST_CASE("flow_classify_ipv6_addresses", "[flow_classify]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Test various IPv6 address types
    struct
    {
        const char* name;
        uint8_t source[16];
        uint8_t dest[16];
    } ipv6_tests[] = {
        {"Loopback",
         {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
         {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
        {"Link-local",
         {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
         {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
        {"Global unicast",
         {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
         {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}},
    };

    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;

    for (const auto& test : ipv6_tests) {
        memcpy(&parameters.source_ipv6_address, test.source, sizeof(test.source));
        memcpy(&parameters.destination_ipv6_address, test.dest, sizeof(test.dest));
        parameters.source_port = 1234;
        parameters.destination_port = 5678;
        parameters.protocol = IPPROTO_TCP;

        client_context->flow_classify_count = 0;
        FWP_ACTION_TYPE result = helper.test_flow_classify_ale_v6(&parameters);
        REQUIRE(result == FWP_ACTION_PERMIT);
        REQUIRE(client_context->flow_classify_count == 1);
    }
}

TEST_CASE("flow_classify_protocol_variations", "[flow_classify]")
{
    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Test different protocols at ALE layer
    struct
    {
        uint8_t protocol;
        const char* name;
        uint16_t port;
    } protocol_tests[] = {
        {IPPROTO_TCP, "TCP", 80},
        {IPPROTO_UDP, "UDP", 53},
        {IPPROTO_ICMP, "ICMP", 0},
    };

    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;

    parameters.source_ipv4_address = 0x7f000001; // 127.0.0.1
    parameters.destination_ipv4_address = 0x7f000001;

    for (const auto& test : protocol_tests) {
        parameters.protocol = test.protocol;
        parameters.source_port = 12345;
        parameters.destination_port = test.port;

        client_context->flow_classify_count = 0;
        FWP_ACTION_TYPE result = helper.test_flow_classify_ale_v4(&parameters);
        REQUIRE(result == FWP_ACTION_PERMIT);
        REQUIRE(client_context->flow_classify_count == 1);

        // Only TCP has stream layer classification
        if (test.protocol == IPPROTO_TCP) {
            client_context->flow_classify_count = 0;
            auto flow_result = static_cast<flow_classify_action_t>(helper.test_flow_classify_stream_v4(&parameters));
            REQUIRE(flow_result == FLOW_CLASSIFY_ALLOW);
            REQUIRE(client_context->flow_classify_count == 1);
        }
    }
}

TEST_CASE("flow_classify_compartment_scenarios", "[flow_classify]")
{
    // Test different compartment ID scenarios
    struct
    {
        uint32_t filter_compartment_id;
        uint32_t flow_compartment_id;
        const char* description;
    } compartment_tests[] = {
        {UNSPECIFIED_COMPARTMENT_ID, 0, "Wildcard filter, default compartment"},
        {UNSPECIFIED_COMPARTMENT_ID, 123, "Wildcard filter, custom compartment"},
        {123, 123, "Specific filter, matching compartment"},
        {456, 456, "Different specific filter, matching compartment"},
    };

    for (const auto& test : compartment_tests) {
        ebpf_extension_data_t npi_specific_characteristics = {
            .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
        };

        if (test.filter_compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
            npi_specific_characteristics.data = &test.filter_compartment_id;
            npi_specific_characteristics.data_size = sizeof(test.filter_compartment_id);
        }

        test_flow_classify_client_context_header_t client_context_header = {0};
        test_flow_classify_client_context_t* client_context = &client_context_header.context;
        fwp_classify_parameters_t parameters = {};

        netebpf_ext_helper_t helper(
            &npi_specific_characteristics,
            (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
            (netebpfext_helper_base_client_context_t*)client_context);

        netebpfext_initialize_fwp_classify_parameters(&parameters);
        parameters.compartment_id = test.flow_compartment_id;

        client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
        client_context->validate_flow_context = true;

        FWP_ACTION_TYPE result = helper.test_flow_classify_ale_v4(&parameters);
        REQUIRE(result == FWP_ACTION_PERMIT);
        REQUIRE(client_context->flow_classify_count >= 1);
    }
}

TEST_CASE("flow_classify_data_pointers", "[flow_classify]")
{
    // Test that flow_classify context properly handles data pointers
    // In real scenarios, data_start and data_end would point to packet data
    netebpf_ext_helper_t helper;
    auto flow_classify_program_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_FLOW_CLASSIFY);
    REQUIRE(flow_classify_program_data != nullptr);

    bpf_flow_classify_t input_context = {};
    input_context.family = AF_INET;
    input_context.local_ip4 = 0x12345678;
    input_context.local_port = 0x1234;
    input_context.remote_ip4 = 0x90abcdef;
    input_context.remote_port = 0x5678;
    input_context.protocol = IPPROTO_TCP;
    input_context.compartment_id = 0;
    input_context.interface_luid = 0;
    input_context.direction = static_cast<uint8_t>(1);
    input_context.flow_id = 0x1111222233334444ULL;
    input_context.data_start = nullptr;
    input_context.data_end = nullptr;

    std::vector<uint8_t> input_data(100);

    bpf_flow_classify_t* flow_classify_context = nullptr;
    REQUIRE(
        flow_classify_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&flow_classify_context) == 0);

    // Initially, data pointers should be null
    REQUIRE(flow_classify_context->data_start == nullptr);
    REQUIRE(flow_classify_context->data_end == nullptr);

    // Simulate setting data pointers (as would happen in stream layer)
    uint8_t dummy_data[100] = {0};
    flow_classify_context->data_start = dummy_data;
    flow_classify_context->data_end = dummy_data + sizeof(dummy_data);

    REQUIRE(flow_classify_context->data_start == dummy_data);
    REQUIRE(flow_classify_context->data_end == dummy_data + sizeof(dummy_data));
    REQUIRE((flow_classify_context->data_end - flow_classify_context->data_start) == sizeof(dummy_data));

    // Clean up
    size_t output_data_size = 0;
    bpf_flow_classify_t output_context = {};
    size_t output_context_size = sizeof(output_context);
    flow_classify_program_data->context_destroy(
        flow_classify_context, nullptr, &output_data_size, (uint8_t*)&output_context, &output_context_size);
}

#pragma endregion flow_classify

TEST_CASE("flow_classify_ale_to_stream_sequence", "[flow_classify]")
{
    // This test demonstrates the proper sequence for testing flow_classify:
    // 1. ALE flow established layer creates flow context
    // 2. Stream layer uses the established flow context for data classification

    ebpf_extension_data_t npi_specific_characteristics = {
        .header = EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION,
    };
    test_flow_classify_client_context_header_t client_context_header = {0};
    test_flow_classify_client_context_t* client_context = &client_context_header.context;
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_flow_callback,
        (netebpfext_helper_base_client_context_t*)client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Configure test flow parameters
    parameters.source_ipv4_address = 0xC0A80101;      // 192.168.1.1
    parameters.destination_ipv4_address = 0xC0A80102; // 192.168.1.2
    parameters.source_port = 32768;
    parameters.destination_port = 8080;
    parameters.protocol = IPPROTO_TCP;

    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_PERMIT;
    client_context->validate_flow_context = true;

    // Phase 1: ALE Flow Established
    // This simulates TCP connection establishment and creates the flow context
    client_context->flow_classify_count = 0;
    FWP_ACTION_TYPE ale_result = helper.test_flow_classify_ale_v4(&parameters);
    REQUIRE(ale_result == FWP_ACTION_PERMIT);
    REQUIRE(client_context->flow_classify_count == 1);

    // Phase 2: Stream Layer Data Classification
    // This simulates processing TCP data segments using the established flow context
    client_context->flow_classify_count = 0;

    // Multiple stream classifications simulating data segments
    for (int segment = 0; segment < 3; segment++) {
        FWP_ACTION_TYPE stream_result = helper.test_flow_classify_stream_v4(&parameters);
        REQUIRE(stream_result == FWP_ACTION_PERMIT);
    }
    REQUIRE(client_context->flow_classify_count == 3);

    // Phase 3: Test different actions at stream layer
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_NEED_MORE_DATA;
    client_context->flow_classify_count = 0;

    FWP_ACTION_TYPE need_more_result = helper.test_flow_classify_stream_v4(&parameters);
    REQUIRE(need_more_result == FWP_ACTION_PERMIT); // NEED_MORE_DATA maps to PERMIT
    REQUIRE(client_context->flow_classify_count == 1);

    // Phase 4: Block subsequent data
    client_context->flow_classify_action = FLOW_CLASSIFY_TEST_ACTION_BLOCK;
    client_context->flow_classify_count = 0;

    FWP_ACTION_TYPE block_result = helper.test_flow_classify_stream_v4(&parameters);
    REQUIRE(block_result == FWP_ACTION_BLOCK);
    REQUIRE(client_context->flow_classify_count == 1);
}
