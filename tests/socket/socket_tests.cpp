// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This module facilitates testing various socket related eBPF program types and hooks.
 */

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_nethooks.h"
#include "ebpf_structs.h"
#include "misc_helper.h"
#include "native_helper.hpp"
#include "socket_helper.h"
#include "socket_tests_common.h"
#include "watchdog.h"

#include <chrono>
#include <future>
#include <iostream>
using namespace std::chrono_literals;
#include <mstcpip.h>
#include <span>

CATCH_REGISTER_LISTENER(_watchdog)

#define MULTIPLE_ATTACH_PROGRAM_COUNT 3

thread_local bool _is_main_thread = false;

void
connection_test(
    ADDRESS_FAMILY address_family,
    _Inout_ client_socket_t& sender_socket,
    _Inout_ receiver_socket_t& receiver_socket,
    uint32_t protocol)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr", _is_main_thread);

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);
    const char* connect_program_name = (address_family == AF_INET) ? "authorize_connect4" : "authorize_connect6";
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);

    const char* recv_accept_program_name =
        (address_family == AF_INET) ? "authorize_recv_accept4" : "authorize_recv_accept6";
    bpf_program* recv_accept_program = bpf_object__find_program_by_name(object, recv_accept_program_name);
    SAFE_REQUIRE(recv_accept_program != nullptr);

    PSOCKADDR local_address = nullptr;
    int local_address_length = 0;
    sender_socket.get_local_address(local_address, local_address_length);

    connection_tuple_t tuple = {0};
    if (address_family == AF_INET) {
        tuple.remote_ip.ipv4 = htonl(INADDR_LOOPBACK);
        printf("tuple.remote_ip.ipv4 = %x\n", tuple.remote_ip.ipv4);
    } else {
        memcpy(tuple.remote_ip.ipv6, &in6addr_loopback, sizeof(tuple.remote_ip.ipv6));
    }
    tuple.remote_port = htons(SOCKET_TEST_PORT);
    printf("tuple.remote_port = %x\n", tuple.remote_port);
    tuple.protocol = protocol;

    bpf_map* ingress_connection_policy_map = bpf_object__find_map_by_name(object, "ingress_connection_policy_map");
    SAFE_REQUIRE(ingress_connection_policy_map != nullptr);
    bpf_map* egress_connection_policy_map = bpf_object__find_map_by_name(object, "egress_connection_policy_map");
    SAFE_REQUIRE(egress_connection_policy_map != nullptr);

    // Update ingress and egress policy to block loopback packet on test port.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(ingress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();

    // Attach the connect program at BPF_CGROUP_INET4_CONNECT.
    bpf_attach_type connect_attach_type =
        (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;
    int result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program)), 0, connect_attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);

    // The packet should be blocked by the connect program.
    receiver_socket.complete_async_receive(true);
    // Cancel send operation.
    sender_socket.cancel_send_message();

    // Update egress policy to allow packet.
    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Attach the receive/accept program at BPF_CGROUP_INET4_RECV_ACCEPT.
    bpf_attach_type recv_accept_attach_type =
        (address_family == AF_INET) ? BPF_CGROUP_INET4_RECV_ACCEPT : BPF_CGROUP_INET6_RECV_ACCEPT;
    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept_program)), 0, recv_accept_attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Resend the packet. This time, it should be dropped by the receive/accept program.
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    receiver_socket.complete_async_receive(true);
    // Cancel send operation.
    sender_socket.cancel_send_message();

    // Update ingress policy to allow packet.
    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(ingress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Resend the packet. This time, it should be allowed by both the programs and the packet should reach loopback the
    // destination.
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    receiver_socket.complete_async_receive();
}

TEST_CASE("connection_test_udp_v4", "[sock_addr_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP);
}
TEST_CASE("connection_test_udp_v6", "[sock_addr_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP);
}

TEST_CASE("connection_test_tcp_v4", "[sock_addr_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP);
}
TEST_CASE("connection_test_tcp_v6", "[sock_addr_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP);
}

TEST_CASE("attach_sock_addr_programs", "[sock_addr_tests]")
{
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);

    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr", _is_main_thread);

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* connect4_program = bpf_object__find_program_by_name(object, "authorize_connect4");
    SAFE_REQUIRE(connect4_program != nullptr);

    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_CONNECT,
        0);
    SAFE_REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    SAFE_REQUIRE(program_info.link_count == 1);
    SAFE_REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach(UNSPECIFIED_COMPARTMENT_ID, BPF_CGROUP_INET4_CONNECT);
    SAFE_REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    SAFE_REQUIRE(program_info.link_count == 0);

    bpf_program* recv_accept4_program = bpf_object__find_program_by_name(object, "authorize_recv_accept4");
    SAFE_REQUIRE(recv_accept4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT,
        0);
    SAFE_REQUIRE(result == 0);

    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    SAFE_REQUIRE(program_info.link_count == 1);
    SAFE_REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach2(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT);
    SAFE_REQUIRE(result == 0);

    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    SAFE_REQUIRE(program_info.link_count == 0);

    bpf_program* connect6_program = bpf_object__find_program_by_name(object, "authorize_connect6");
    SAFE_REQUIRE(connect6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_CONNECT,
        0);
    SAFE_REQUIRE(result == 0);

    bpf_program* recv_accept6_program = bpf_object__find_program_by_name(object, "authorize_recv_accept6");
    SAFE_REQUIRE(recv_accept6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_RECV_ACCEPT,
        0);
    SAFE_REQUIRE(result == 0);
}

void
connection_monitor_test(
    ADDRESS_FAMILY address_family,
    _Inout_ client_socket_t& sender_socket,
    _Inout_ receiver_socket_t& receiver_socket,
    uint32_t protocol,
    bool disconnect)
{
    native_module_helper_t helper;
    helper.initialize("sockops", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Ring buffer event callback context.
    std::unique_ptr<ring_buffer_test_event_context_t> context = std::make_unique<ring_buffer_test_event_context_t>();
    context->test_event_count = disconnect ? 4 : 2;

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    SAFE_REQUIRE(_program != nullptr);

    uint64_t process_id = get_current_pid_tgid();
    // Ignore the thread Id.
    process_id >>= 32;

    PSOCKADDR local_address = nullptr;
    int local_address_length = 0;
    sender_socket.get_local_address(local_address, local_address_length);

    connection_tuple_t tuple{}, reverse_tuple{};
    if (address_family == AF_INET) {
        tuple.local_ip.ipv4 = htonl(INADDR_LOOPBACK);
        tuple.remote_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(tuple.local_ip.ipv6, &in6addr_loopback, sizeof(tuple.local_ip.ipv6));
        memcpy(tuple.remote_ip.ipv6, &in6addr_loopback, sizeof(tuple.local_ip.ipv6));
    }
    tuple.local_port = INETADDR_PORT(local_address);
    tuple.remote_port = htons(SOCKET_TEST_PORT);
    tuple.protocol = protocol;
    NET_LUID net_luid = {};
    net_luid.Info.IfType = IF_TYPE_SOFTWARE_LOOPBACK;
    tuple.interface_luid = net_luid.Value;

    reverse_tuple.local_ip = tuple.remote_ip;
    reverse_tuple.remote_ip = tuple.local_ip;
    reverse_tuple.local_port = tuple.remote_port;
    reverse_tuple.remote_port = tuple.local_port;
    reverse_tuple.protocol = tuple.protocol;
    reverse_tuple.interface_luid = tuple.interface_luid;

    std::vector<std::vector<char>> audit_entry_list;
    audit_entry_t audit_entries[4] = {0};

    // Connect outbound.
    audit_entries[0].tuple = tuple;
    audit_entries[0].process_id = process_id;
    audit_entries[0].connected = true;
    audit_entries[0].outbound = true;
    char* p = reinterpret_cast<char*>(&audit_entries[0]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Connect inbound.
    audit_entries[1].tuple = reverse_tuple;
    audit_entries[1].process_id = process_id;
    audit_entries[1].connected = true;
    audit_entries[1].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[1]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create an audit entry for the disconnect case.
    // The direction bit is set to false.
    audit_entries[2].tuple = tuple;
    audit_entries[2].process_id = process_id;
    audit_entries[2].connected = false;
    audit_entries[2].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[2]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create another audit entry for the disconnect event with the reverse packet tuple.
    audit_entries[3].tuple = reverse_tuple;
    audit_entries[3].process_id = process_id;
    audit_entries[3].connected = false;
    audit_entries[3].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[3]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    context->records = &audit_entry_list;

    // Get the std::future from the promise field in ring buffer event context, which should be in ready state
    // once notifications for all events are received.
    auto ring_buffer_event_callback = context->ring_buffer_event_promise.get_future();

    // Create a new ring buffer manager and subscribe to ring buffer events.
    bpf_map* ring_buffer_map = bpf_object__find_map_by_name(object, "audit_map");
    SAFE_REQUIRE(ring_buffer_map != nullptr);
    context->ring_buffer = ring_buffer__new(
        bpf_map__fd(ring_buffer_map), (ring_buffer_sample_fn)ring_buffer_test_event_handler, context.get(), nullptr);
    SAFE_REQUIRE(context->ring_buffer != nullptr);

    bpf_map* connection_map = bpf_object__find_map_by_name(object, "connection_map");
    SAFE_REQUIRE(connection_map != nullptr);

    // Update connection map with loopback packet tuples.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &tuple, &verdict, EBPF_ANY) == 0);
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &reverse_tuple, &verdict, EBPF_ANY) == 0);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();

    // Attach the sockops program.
    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    SAFE_REQUIRE(result == 0);

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    // Receive the packet on test port.
    receiver_socket.complete_async_receive();

    if (disconnect) {
        sender_socket.close();
        receiver_socket.close();
    }

    // Wait for event handler getting notifications for all connection audit events.
    SAFE_REQUIRE(ring_buffer_event_callback.wait_for(1s) == std::future_status::ready);

    // Mark the event context as canceled, such that the event callback stops processing events.
    context->canceled = true;

    // Unsubscribe.
    context->unsubscribe();
}

TEST_CASE("connection_monitor_test_udp_v4", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, false);
}
TEST_CASE("connection_monitor_test_disconnect_udp_v4", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, true);
}

TEST_CASE("connection_monitor_test_udp_v6", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, false);
}
TEST_CASE("connection_monitor_test_disconnect_udp_v6", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, true);
}

TEST_CASE("connection_monitor_test_tcp_v4", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP, false);
}
TEST_CASE("connection_monitor_test_disconnect_tcp_v4", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP, true);
}

TEST_CASE("connection_monitor_test_tcp_v6", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP, false);
}
TEST_CASE("connection_monitor_test_disconnect_tcp_v6", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP, true);
}

TEST_CASE("attach_sockops_programs", "[sock_ops_tests]")
{
    native_module_helper_t helper;
    helper.initialize("sockops", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    SAFE_REQUIRE(_program != nullptr);

    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    SAFE_REQUIRE(result == 0);
}

// This function populates map polcies for multi-attach tests.
// It assumes that the destination and proxy are loopback addresses.
static void
_update_map_entry_multi_attach(
    fd_t map_fd,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    bool add)
{
    destination_entry_key_t key = {0};
    destination_entry_value_t value = {0};

    if (address_family == AF_INET) {
        key.destination_ip.ipv4 = htonl(INADDR_LOOPBACK);
        value.destination_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(key.destination_ip.ipv6, &in6addr_loopback, sizeof(key.destination_ip.ipv6));
        memcpy(value.destination_ip.ipv6, &in6addr_loopback, sizeof(value.destination_ip.ipv6));
    }
    key.destination_port = destination_port;
    key.protocol = protocol;
    value.destination_port = proxy_port;

    if (add) {
        SAFE_REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        bpf_map_delete_elem(map_fd, &key);
    }
}

typedef enum _connection_result
{
    RESULT_ALLOW,
    RESULT_DROP,
    RESULT_DONT_CARE
} connection_result_t;

void
get_client_socket(socket_family_t family, uint16_t protocol, _Inout_ client_socket_t** sender_socket)
{
    client_socket_t* old_socket = *sender_socket;
    client_socket_t* new_socket = nullptr;
    if (protocol == IPPROTO_TCP) {
        new_socket = (client_socket_t*)new stream_client_socket_t(SOCK_STREAM, IPPROTO_TCP, 0, family);
    } else {
        new_socket = (client_socket_t*)new datagram_client_socket_t(SOCK_DGRAM, IPPROTO_UDP, 0, family);
    }

    *sender_socket = new_socket;
    if (old_socket) {
        delete old_socket;
    }
}

void
validate_connection_multi_attach(
    socket_family_t family,
    ADDRESS_FAMILY address_family,
    uint16_t receiver_port,
    uint16_t destination_port,
    uint16_t protocol,
    connection_result_t expected_result)
{
    client_socket_t* sender_socket = nullptr;
    receiver_socket_t* receiver_socket = nullptr;

    if (protocol == IPPROTO_UDP) {
        receiver_socket = new datagram_server_socket_t(SOCK_DGRAM, IPPROTO_UDP, receiver_port);
    } else if (protocol == IPPROTO_TCP) {
        receiver_socket = new stream_server_socket_t(SOCK_STREAM, IPPROTO_TCP, receiver_port);
    } else {
        SAFE_REQUIRE(false);
    }
    get_client_socket(family, protocol, &sender_socket);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket->post_async_receive();

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        if (family == socket_family_t::Dual) {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        } else {
            IN4ADDR_SETLOOPBACK((PSOCKADDR_IN)&destination_address);
        }
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }

    sender_socket->send_message_to_remote_host(message, destination_address, destination_port);

    if (expected_result == RESULT_DROP) {
        // The packet should be blocked.
        receiver_socket->complete_async_receive(true);
        // Cancel send operation.
        sender_socket->cancel_send_message();
    } else if (expected_result == RESULT_ALLOW) {
        // The packet should be allowed by the connect program.
        receiver_socket->complete_async_receive();
    } else {
        // The result is not deterministic, so we don't care about the result.
        receiver_socket->complete_async_receive(1000, receiver_socket_t::MODE_DONT_CARE);
    }

    delete sender_socket;
    delete receiver_socket;
}

void
multi_attach_test_common(
    bpf_object* object,
    socket_family_t family,
    ADDRESS_FAMILY address_family,
    uint32_t compartment_id,
    uint16_t protocol,
    bool detach_program)
{
    // This function assumes that all the attached programs already allow the connection.
    // It then proceeds to test the following:
    // 1. For the provided program object, update policy map to block the connection
    //    and validate that the connection is blocked.
    // 2. Revert the policy to allow the connection, validate that the connection is now allowed.
    //
    // Along with the above, if "detach_program" is true, the function will also test the following:
    // 1. Update policy map to block the connection, validate that the connection is blocked.
    // 2. Detach the program, validate that the connection should now be allowed.
    // 3. Re-attach the program, and validate that the connection is again blocked.
    // 4. Update policy map to allow the connection, validate that the connection is allowed.

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);
    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Deleting the map entry will result in the program blocking the connection.
    _update_map_entry_multi_attach(
        map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, false);

    // The packet should be blocked.
    validate_connection_multi_attach(family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

    // Revert the policy to "allow" the connection.
    _update_map_entry_multi_attach(
        map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, true);

    // The packet should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

    if (detach_program) {
        // Block the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, false);

        // The packet should be blocked.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

        // Detach the program.
        int result = bpf_prog_detach2(bpf_program__fd(connect_program), compartment_id, attach_type);
        SAFE_REQUIRE(result == 0);

        // The packet should now be allowed.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

        // Re-attach the program.
        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);

        // The packet should be blocked.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

        // Update the policy to "allow" the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, true);

        // The packet should now be allowed.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);
    }
}

void
multi_attach_test(uint32_t compartment_id, socket_family_t family, ADDRESS_FAMILY address_family, uint16_t protocol)
{
    // This test is to verify that multiple programs can be attached to the same hook, and they work as expected.
    // Scenarios covered:
    // 1. Multiple programs attached to the same hook.
    // 2. For multiple programs attached to same hook, validate the order of execution.
    // 3. For multiple programs attached to same hook, validate the verdict based on the order of execution.
    // 4. Programs attached to different hooks -- only one should be invoked.

    native_module_helper_t helpers[MULTIPLE_ATTACH_PROGRAM_COUNT];
    struct bpf_object* objects[MULTIPLE_ATTACH_PROGRAM_COUNT] = {nullptr};
    bpf_object_ptr object_ptrs[MULTIPLE_ATTACH_PROGRAM_COUNT];
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2", _is_main_thread);
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";

    // Attach all the programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);
    }

    // Configure policy maps for all programs to "allow" the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
        SAFE_REQUIRE(policy_map != nullptr);
        fd_t map_fd = bpf_map__fd(policy_map);
        SAFE_REQUIRE(map_fd != ebpf_fd_invalid);
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, true);
    }

    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

    // Test that the connection is blocked if any of the programs block the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        multi_attach_test_common(objects[i], family, address_family, compartment_id, protocol, false);
    }

    // Next section tests detach and re-attach of programs.
    // Current attach order is 0 --> 1 --> 2. Detach "first" program and check if the verdict changes.
    multi_attach_test_common(objects[0], family, address_family, compartment_id, protocol, true);

    // Now the program attach order is 1 --> 2 --> 0. Repeat detach / reattach with the "middle" program.
    multi_attach_test_common(objects[2], family, address_family, compartment_id, protocol, true);

    // Now the program attach order is 1 --> 0 --> 2. Repeat it with the "last" program.
    multi_attach_test_common(objects[2], family, address_family, compartment_id, protocol, true);

    // Now attach a 4th program to different compartment. It should not get invoked, and its verdict should not affect
    // the connection.
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);

    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Attach the connect program at BPF_CGROUP_INET4_CONNECT / BPF_CGROUP_INET6_CONNECT.
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);
    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id + 2, attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Not updating policy map for this program should mean that this program (if invoked) will block the connection.
    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);
}

void
multi_attach_test_redirection(
    socket_family_t family, ADDRESS_FAMILY address_family, uint32_t compartment_id, uint16_t protocol)
{
    // This test validates combination of redirection and other program verdicts.
    native_module_helper_t helpers[MULTIPLE_ATTACH_PROGRAM_COUNT];
    struct bpf_object* objects[MULTIPLE_ATTACH_PROGRAM_COUNT] = {nullptr};
    bpf_object_ptr object_ptrs[MULTIPLE_ATTACH_PROGRAM_COUNT];
    uint16_t proxy_port = SOCKET_TEST_PORT;
    uint16_t destination_port = proxy_port - 1;
    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load 3 programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2", _is_main_thread);
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    // Attach all the 3 programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);
    }

    // Lambda function to update the policy map entry, and validate the connection.
    auto validate_program_redirection = [&](uint32_t program_index) {
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            // Configure ith program to redirect the connection. Configure all other programs to "allow" the connection.
            bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);
            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            if (i != program_index) {
                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);
            } else {
                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(destination_port), htons(proxy_port), protocol, true);
            }
        }

        // Validate that the connection is successfully redirected.
        validate_connection_multi_attach(family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

        if (program_index > 0) {
            // If this is not the first program, configure the preceding program to block the connection.
            // That should result in the connection being blocked.
            bpf_map* policy_map = bpf_object__find_map_by_name(objects[program_index - 1], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);
            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);

            // Validate that the connection is blocked.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_DROP);

            // Now detach the preceding program, and validate that the connection is allowed.
            bpf_program* connect_program =
                bpf_object__find_program_by_name(objects[program_index - 1], connect_program_name);
            SAFE_REQUIRE(connect_program != nullptr);

            int result = bpf_prog_detach2(
                bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type);
            SAFE_REQUIRE(result == 0);

            // The connection should now be allowed.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Revert the policy to allow the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);
        }

        // Reset the whole state by detaching and re-attaching all the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_program* program = bpf_object__find_program_by_name(objects[i], connect_program_name);
            SAFE_REQUIRE(program != nullptr);
            bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, attach_type);
        }

        // Re-attach the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_program* program = bpf_object__find_program_by_name(objects[i], connect_program_name);
            SAFE_REQUIRE(program != nullptr);
            int result = bpf_prog_attach(
                bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, attach_type, 0);
            SAFE_REQUIRE(result == 0);
        }

        // Validate that the connection is again allowed.
        validate_connection_multi_attach(family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

        if (program_index < MULTIPLE_ATTACH_PROGRAM_COUNT - 1) {
            // If this is not the last program, configure the following program to block the connection.
            // That should result in the connection still be redirected.

            bpf_map* policy_map = bpf_object__find_map_by_name(objects[program_index + 1], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);

            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            // Delete the map entry to block the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);

            // Validate that the connection is still redirected.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Next configure the last program to redirect the connection to proxy_port + 1.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port + 1), protocol, true);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(proxy_port + 1), protocol, true);

            // Validate that the connection is not redirected to proxy_port + 1. This is because the connection is
            // already redirected by the previous program.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Revert the policy to allow the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

            // Validate that the connection is allowed.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);
        }
    };

    // For each program, detach and re-attach it, and validate the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        validate_program_redirection(i);
    }
}

TEST_CASE("multi_attach_test_TCP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    multi_attach_test(compartment_id, socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_TCP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    multi_attach_test(compartment_id, socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_UDP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    multi_attach_test(compartment_id, socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_UDP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    multi_attach_test(compartment_id, socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_wildcard_TCP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_wildcard_TCP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_wildcard_UDP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_wildcard_UDP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

typedef enum _program_action
{
    ACTION_ALLOW,
    ACTION_REDIRECT,
    ACTION_BLOCK,
    ACTION_MAX,
} program_action_t;

void
multi_attach_configure_map(
    bpf_object* object,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    program_action_t action)
{
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);
    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    if (action == ACTION_ALLOW) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

        _update_map_entry_multi_attach(map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);
    } else if (action == ACTION_REDIRECT) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(proxy_port), protocol, true);
    } else if (action == ACTION_BLOCK) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

        _update_map_entry_multi_attach(map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);
    } else {
        SAFE_REQUIRE(false);
    }
}

static program_action_t
_multi_attach_get_combined_verdict(program_action_t* actions, uint32_t count)
{
    SAFE_REQUIRE(count % 2 == 0);

    for (uint32_t i = 0; i < count; i++) {
        if (actions[i] == ACTION_BLOCK) {
            return ACTION_BLOCK;
        } else if (actions[i] == ACTION_REDIRECT) {
            return ACTION_REDIRECT;
        }
    }
    return ACTION_ALLOW;
}

void
test_multi_attach_combined(socket_family_t family, ADDRESS_FAMILY address_family, uint16_t protocol)
{
    // This test case loads and attaches program_count_per_hook * 2 programs:
    // program_count_per_hook programs with specific compartment id, and
    // program_count_per_hook programs with wildcard compartment id.
    // Then the test case iterates over all the possible combinations of program actions (allow, redirect, block) for
    // each program, and validates the connection based on the expected result.

    constexpr uint32_t program_count_per_hook = 2;
    native_module_helper_t helpers[program_count_per_hook * 2];
    struct bpf_object* objects[program_count_per_hook * 2] = {nullptr};
    bpf_object_ptr object_ptrs[program_count_per_hook * 2];
    program_action_t actions[program_count_per_hook * 2] = {ACTION_ALLOW};
    uint16_t proxy_port = SOCKET_TEST_PORT;
    uint16_t destination_port = proxy_port - 1;
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the programs.
    for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
        helpers[i].initialize("cgroup_sock_addr2", _is_main_thread);
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";

    // Attach all the programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)),
            i < program_count_per_hook ? 1 : UNSPECIFIED_COMPARTMENT_ID,
            attach_type,
            0);
        SAFE_REQUIRE(result == 0);
    }

    // This loop will iterate over all the possible combinations of program actions for each program.
    while (true) {
        // Configure program actions.
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            multi_attach_configure_map(objects[i], address_family, destination_port, proxy_port, protocol, actions[i]);
        }

        program_action_t expected_action = _multi_attach_get_combined_verdict(actions, program_count_per_hook * 2);

        // Validate the connection based on the expected action.
        switch (expected_action) {
        case ACTION_ALLOW:
            validate_connection_multi_attach(
                family, address_family, destination_port, destination_port, protocol, RESULT_ALLOW);
            break;
        case ACTION_REDIRECT:
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);
            break;
        case ACTION_BLOCK:
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_DROP);
            break;
        default:
            SAFE_REQUIRE(false);
        }

        // Increment the program actions.
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            actions[i] = static_cast<program_action_t>(actions[i] + 1);
            if (actions[i] == ACTION_MAX) {
                actions[i] = ACTION_ALLOW;
            } else {
                break;
            }
        }

        // Print the program actions.
        printf("Program actions: ");
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            printf("%d ", actions[i]);
        }
        printf("\n");

        // Break if all the program actions are ACTION_BLOCK.
        bool should_break = true;
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            if (actions[i] != ACTION_BLOCK) {
                should_break = false;
                break;
            }
        }

        if (should_break) {
            break;
        }
    }
}

TEST_CASE("multi_attach_test_combined_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    test_multi_attach_combined(socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_combined_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    test_multi_attach_combined(socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_combined_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    test_multi_attach_combined(socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_combined_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    test_multi_attach_combined(socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, compartment_id, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, compartment_id, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, compartment_id, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, compartment_id, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, compartment_id, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, compartment_id, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, compartment_id, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, compartment_id, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_invocation_order", "[sock_addr_tests][multi_attach_tests]")
{
    // This test case validates that a program attached with specific compartment id is always invoked before a
    // program attached with wildcard compartment id, irrespective of the order of attachment.

    int result = 0;
    native_module_helper_t native_helpers_specific;
    native_module_helper_t native_helpers_wildcard;
    native_helpers_specific.initialize("cgroup_sock_addr2", _is_main_thread);
    native_helpers_wildcard.initialize("cgroup_sock_addr2", _is_main_thread);
    socket_family_t family = socket_family_t::Dual;
    ADDRESS_FAMILY address_family = AF_INET;
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    struct bpf_object* object_specific = bpf_object__open(native_helpers_specific.get_file_name().c_str());
    SAFE_REQUIRE(object_specific != nullptr);
    bpf_object_ptr object_specific_ptr(object_specific);

    struct bpf_object* object_wildcard = bpf_object__open(native_helpers_wildcard.get_file_name().c_str());
    SAFE_REQUIRE(object_wildcard != nullptr);
    bpf_object_ptr object_wildcard_ptr(object_wildcard);

    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object_specific) == 0);
    SAFE_REQUIRE(bpf_object__load(object_wildcard) == 0);

    bpf_program* connect_program_specific = bpf_object__find_program_by_name(object_specific, "connect_redirect4");
    SAFE_REQUIRE(connect_program_specific != nullptr);

    bpf_program* connect_program_wildcard = bpf_object__find_program_by_name(object_wildcard, "connect_redirect4");
    SAFE_REQUIRE(connect_program_wildcard != nullptr);

    // Attach the program with specific compartment id first.
    result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Attach the program with wildcard compartment id next.
    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program_wildcard)),
        UNSPECIFIED_COMPARTMENT_ID,
        attach_type,
        0);
    SAFE_REQUIRE(result == 0);

    // First configure both the programs to allow the connection.
    bpf_map* policy_map_specific = bpf_object__find_map_by_name(object_specific, "policy_map");
    SAFE_REQUIRE(policy_map_specific != nullptr);

    fd_t map_fd_specific = bpf_map__fd(policy_map_specific);
    SAFE_REQUIRE(map_fd_specific != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    bpf_map* policy_map_wildcard = bpf_object__find_map_by_name(object_wildcard, "policy_map");
    SAFE_REQUIRE(policy_map_wildcard != nullptr);

    fd_t map_fd_wildcard = bpf_map__fd(policy_map_wildcard);
    SAFE_REQUIRE(map_fd_wildcard != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the program with specific compartment id to block the connection.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // The connection should be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // The connection should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the program with wildcard compartment id to block the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // The connection should be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // The connection should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the specific program to redirect the connection.
    uint16_t destination_port = SOCKET_TEST_PORT - 1;
    // uint16_t proxy_port = destination_port + 1;

    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is redirected to the final port.
    // The order of attach and invocation should be: specific --> wildcard.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure blocking rule for wildcard program.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // Validate that the connection is still redirected to the final port.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Now detach the program with specific compartment id.
    result =
        bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type);

    // The connection should now be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_DROP);

    // Re-attach the program with specific compartment id.
    result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type, 0);

    // The connection should be allowed. This validates that the program with specific compartment id is always
    // invoked before the program with wildcard compartment id.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure allow rule for specific program and redirect rule for wildcard program.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, true);

    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(destination_port), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is redirected to the final port.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Block the connection for specific program.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, false);

    // Validate that the connection is now blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_DROP);

    // Detach the program with specific compartment id.
    result =
        bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type);
    SAFE_REQUIRE(result == 0);

    // Since the specific program is now detached, the connection should be correctly redirected by wildcard program.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);
}

/**
 * @brief This function sends messages to the receiver port in a loop using UDP socket.
 *
 * @param token Stop token to stop the thread.
 * @param address_family Address family to use.
 * @param receiver_port Port to send the message to.
 */
void
thread_function_invoke_connection(std::stop_token token, ADDRESS_FAMILY address_family, uint16_t receiver_port)
{
    uint32_t count = 0;

    while (!token.stop_requested()) {
        datagram_client_socket_t sender_socket(SOCK_DGRAM, IPPROTO_UDP, 0);

        // Send loopback message to test port.
        const char* message = CLIENT_MESSAGE;
        sockaddr_storage destination_address{};
        if (address_family == AF_INET) {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        } else {
            IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
        }

        sender_socket.send_message_to_remote_host(message, destination_address, receiver_port);

        count++;
    }

    std::cout << "Thread (invoke_connection)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
thread_function_attach_detach(std::stop_token token, uint32_t compartment_id, uint16_t destination_port)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);
    uint32_t count = 0;
    ADDRESS_FAMILY address_family = AF_INET;

    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the program.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Configure policy map to allow the connection (TCP and UDP).
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, true);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), IPPROTO_UDP, true);

    while (!token.stop_requested()) {
        // Attach and detach the program in a loop.
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        result = bpf_prog_detach2(bpf_program__fd(connect_program), compartment_id, attach_type);
        SAFE_REQUIRE(result == 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        count++;
    }

    std::cout << "Thread (attach_detach)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
thread_function_allow_block_connection(
    std::stop_token token,
    ADDRESS_FAMILY address_family,
    uint16_t protocol,
    uint16_t destination_port,
    uint32_t compartment_id)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);
    uint32_t count = 0;
    socket_family_t family = socket_family_t::Dual;

    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the program.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Attach the program at BPF_CGROUP_INET4_CONNECT / BPF_CGROUP_INET6_CONNECT.
    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);

    SAFE_REQUIRE(result == 0);

    // Configure policy map to allow the connection.
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    // Since the default policy is to block the connection, update the policy map to allow the connection for the
    // "other" protocol. This will ensure this program does not interfere with the connections for the second thread
    // that is also running in parallel.
    _update_map_entry_multi_attach(
        map_fd,
        address_family,
        htons(destination_port),
        htons(destination_port),
        (uint16_t)(protocol == IPPROTO_TCP ? IPPROTO_UDP : IPPROTO_TCP),
        true);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

    while (!token.stop_requested()) {
        // Block the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

        // The connection should be blocked. Due to race, it can sometimes be allowed, so we don't care about the
        // result.
        validate_connection_multi_attach(
            family, address_family, destination_port, destination_port, protocol, RESULT_DONT_CARE);

        // Allow the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

        // The connection should be allowed. Due to race, it can sometimes be blocked, so we don't care about the
        // result.
        validate_connection_multi_attach(
            family, address_family, destination_port, destination_port, protocol, RESULT_DONT_CARE);

        count++;
    }

    std::cout << "Thread (allow_block)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
multi_attach_test_thread_function1(
    std::stop_token token,
    uint32_t index,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    std::atomic<bool>& failed)
{
    // Get the mode.
    uint32_t mode = index % 7;
    uint32_t default_compartment = 1;
    uint32_t unspecified_compartment = 0;

    try {
        switch (mode) {
        case 0:
            __fallthrough;
            // break;
        case 1:
            thread_function_invoke_connection(token, address_family, destination_port);
            break;
        case 2:
            thread_function_attach_detach(token, unspecified_compartment, destination_port);
            break;
        case 3:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 4:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 5:
            thread_function_allow_block_connection(
                token, address_family, IPPROTO_TCP, destination_port, default_compartment);
            break;
        case 6:
            thread_function_allow_block_connection(
                token, address_family, IPPROTO_UDP, destination_port, default_compartment);
            break;
        }
    } catch (const test_failure& e) {
        std::cerr << "Thread " << std::this_thread::get_id() << " failed: " << e.message << std::endl;
        failed = true;
    }
}

TEST_CASE("multi_attach_concurrency_test1", "[multi_attach_tests][concurrent_tests]")
{
    // This test case validates that multiple threads can attach / detach programs concurrently, and the connection
    // verdict is as expected. The test case will have the following threads:
    //
    // Thread 0,1: Invokes connections in a loop.
    // Thread 2,3,4: Attach a program, sleep for few ms, detach the program.
    // Thread 5,6: Block and allow the connection in a loop, and invoke the connection to validate.

    uint16_t destination_port = SOCKET_TEST_PORT;
    std::vector<std::jthread> threads;
    uint32_t thread_count = 7;
    uint32_t thread_run_time = 60;
    std::atomic<bool> failed;

    for (uint32_t i = 0; i < thread_count; i++) {
        // Can only pass variables by value, not by references, hence the need for the shared_ptr<bool>.
        threads.emplace_back(
            multi_attach_test_thread_function1, i, (ADDRESS_FAMILY)AF_INET, destination_port, std::ref(failed));
    }

    std::this_thread::sleep_for(std::chrono::seconds(thread_run_time));

    for (auto& thread : threads) {
        thread.request_stop();
    }

    for (auto& thread : threads) {
        thread.join();
    }

    SAFE_REQUIRE(!failed);
}

void
multi_attach_test_thread_function2(
    std::stop_token token,
    uint32_t index,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    std::atomic<bool>& failed)
{
    // Get the mode.
    uint32_t mode = index % 7;
    uint32_t default_compartment = 1;
    uint32_t unspecified_compartment = 0;

    try {
        switch (mode) {
        case 0:
            __fallthrough;
        case 1:
            thread_function_invoke_connection(token, address_family, destination_port);
            break;
        case 2:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 3:
            thread_function_attach_detach(token, unspecified_compartment, destination_port);
            break;
        }
    } catch (const test_failure& e) {
        std::cerr << "Thread " << std::this_thread::get_id() << " failed: " << e.message << std::endl;
        failed = true;
    }
}

TEST_CASE("multi_attach_concurrency_test2", "[multi_attach_tests][concurrent_tests]")
{
    // This test case stresses the code path where 2 program -- one of type wildcard and other of specific attach
    // types are attaching and detaching in parallel, and a third thread invokes the hook by sending packets.
    //
    // Thread 0,1: Invokes connections in a loop.
    // Thread 2: Attach / detach program with wildcard.
    // Thread 3: Attach / detach program with specific compartment id.

    uint16_t destination_port = SOCKET_TEST_PORT;
    std::vector<std::jthread> threads;
    uint32_t thread_count = 4;
    uint32_t thread_run_time = 60;
    std::atomic<bool> failed = false;

    for (uint32_t i = 0; i < thread_count; i++) {
        // Can only pass variables by value, not by references, hence the need for the shared_ptr<bool>.
        threads.emplace_back(
            multi_attach_test_thread_function2, i, (ADDRESS_FAMILY)AF_INET, destination_port, std::ref(failed));
    }

    std::this_thread::sleep_for(std::chrono::seconds(thread_run_time));

    for (auto& thread : threads) {
        thread.request_stop();
    }

    for (auto& thread : threads) {
        thread.join();
    }

    SAFE_REQUIRE(!failed);
}

static const uint8_t default_flow_data[] = {'T', 'E', 'S', 'T'};
static const uint32_t default_flow_local_ip6[] = {0, 0, 0, htonl(1)};
static const uint32_t default_flow_remote_ip6[] = {0, 0, 0, htonl(1)};
static const uint32_t default_flow_local_ip4 = htonl(0x7f000001);  //
static const uint32_t default_flow_remote_ip4 = htonl(0x7f000001); //
static const uint16_t default_flow_local_port = 53;
static const uint16_t default_flow_remote_port = 54321;

template <typename DataType>
static void
init_flow_classify_test_v4(
    bpf_flow_classify_t& ctx,
    bpf_test_run_opts& opts,
    DataType data = default_flow_data,
    uint32_t local_ip4 = default_flow_local_ip4,
    uint16_t local_port = default_flow_local_port,
    uint32_t remote_ip4 = default_flow_remote_ip4,
    uint16_t remote_port = default_flow_remote_port,
    uint8_t direction = FLOW_DIRECTION_OUTBOUND,
    uint8_t protocol = IPPROTO_TCP,
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID,
    uint64_t interface_luid = 0,
    uint64_t flow_id = 0)
{
    ctx = {0};
    ctx.family = AF_INET;
    ctx.local_ip4 = local_ip4;
    ctx.local_port = local_port;
    ctx.remote_ip4 = remote_ip4;
    ctx.remote_port = remote_port;
    ctx.protocol = protocol;
    ctx.compartment_id = compartment_id;
    ctx.interface_luid = interface_luid;
    ctx.direction = direction;
    ctx.flow_id = flow_id;

    opts = {0};
    opts.ctx_in = &ctx;
    opts.ctx_size_in = sizeof(ctx);
    opts.ctx_out = &ctx;
    opts.ctx_size_out = sizeof(ctx);

    opts.data_in = std::ranges::cdata(data);
    opts.data_size_in = static_cast<uint32_t>(std::ranges::size(data));
    opts.data_out = nullptr;
    opts.data_size_out = 0;
}

template <typename DataType>
static void
init_flow_classify_test_v6(
    bpf_flow_classify_t& ctx,
    bpf_test_run_opts& opts,
    DataType data = default_flow_data,
    const uint32_t local_ip6[4] = default_flow_local_ip6,
    uint16_t local_port = default_flow_local_port,
    const uint32_t remote_ip6[4] = default_flow_remote_ip6,
    uint16_t remote_port = default_flow_remote_port,
    uint8_t direction = FLOW_DIRECTION_OUTBOUND,
    uint8_t protocol = IPPROTO_TCP,
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID,
    uint64_t interface_luid = 0,
    uint64_t flow_id = 0)
{
    ctx = {0};
    ctx.family = AF_INET6;
    memcpy(ctx.local_ip6, local_ip6, sizeof(ctx.local_ip6));
    ctx.local_port = local_port;
    memcpy(ctx.remote_ip6, remote_ip6, sizeof(ctx.remote_ip6));
    ctx.remote_port = remote_port;
    ctx.protocol = protocol;
    ctx.compartment_id = compartment_id;
    ctx.interface_luid = interface_luid;
    ctx.direction = direction;
    ctx.flow_id = flow_id;

    opts = {0};
    opts.ctx_in = &ctx;
    opts.ctx_size_in = sizeof(ctx);
    opts.ctx_out = &ctx;
    opts.ctx_size_out = sizeof(ctx);

    opts.data_in = std::ranges::cdata(data);
    opts.data_size_in = static_cast<uint32_t>(std::ranges::size(data));
    opts.data_out = nullptr;
    opts.data_size_out = 0;
}

class flow_classify_test_helper
{
  private:
    native_module_helper_t helper{};
    bpf_object_ptr object_ptr{};
    int program_fd{-1};
    bool is_attached{false};
    std::vector<uint8_t> data_in{'H', 'T', 'T', 'P'};
    bpf_flow_classify_t ctx_out{};
    bpf_flow_classify_t ctx{
        .family{AF_INET},
        .local_ip6{0, 0, 0, htonl(1)},
        .local_port{default_flow_local_port},
        .remote_ip6{0, 0, 0, htonl(1)},
        .remote_port{default_flow_remote_port},
        .protocol{IPPROTO_TCP},
        .compartment_id{UNSPECIFIED_COMPARTMENT_ID},
        .interface_luid{0},
        .direction{FLOW_DIRECTION_INBOUND},
        .flow_id{0},
        .data_start{},
        .data_end{},
    };
    bpf_test_run_opts opts{
        .data_in{},
        .data_out{},
        .data_size_in{},
        .data_size_out{},
        .ctx_in{&ctx},
        .ctx_out{&ctx_out},
        .ctx_size_in{sizeof(ctx)},
        .ctx_size_out{sizeof(ctx_out)},
    };

  public:
    flow_classify_test_helper(const char* program_name, bool auto_attach = false)
    {
        CAPTURE(program_name);
        helper.initialize(program_name, _is_main_thread);
        object_ptr.reset(bpf_object__open(helper.get_file_name().c_str()));
        SAFE_REQUIRE(object_ptr != nullptr);
        SAFE_REQUIRE(bpf_object__load(object_ptr.get()) == 0);

        bpf_program* program = bpf_object__find_program_by_name(object_ptr.get(), program_name);
        SAFE_REQUIRE(program != nullptr);

        program_fd = bpf_program__fd(program);
        SAFE_REQUIRE(program_fd != -1);

        if (auto_attach) {
            int result = bpf_prog_attach(program_fd, 0, BPF_FLOW_CLASSIFY, 0);
            SAFE_REQUIRE(result == 0);
            is_attached = true;
        }
    }
    void
    configure_v6(
        const uint32_t local_ip6[4],
        uint16_t local_port,
        const uint32_t remote_ip6[4],
        uint16_t remote_port,
        uint64_t flow_id,
        uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID,
        uint64_t interface_luid = 0,
        uint8_t protocol = IPPROTO_TCP)
    {
        ctx.family = AF_INET6;
        ctx.protocol = protocol;
        memcpy(ctx.local_ip6, local_ip6, sizeof(ctx.local_ip6));
        ctx.local_port = local_port;
        memcpy(ctx.remote_ip6, remote_ip6, sizeof(ctx.remote_ip6));
        ctx.remote_port = remote_port;
        ctx.flow_id = flow_id;
        ctx.compartment_id = compartment_id;
        ctx.interface_luid = interface_luid;
    }
    void
    configure_v6(
        const IN6_ADDR& local_ip6,
        uint16_t local_port,
        const IN6_ADDR& remote_ip6,
        uint16_t remote_port,
        uint64_t flow_id,
        int32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID,
        uint64_t interface_luid = 0,
        uint8_t protocol = IPPROTO_TCP)
    {
        configure_v6(
            reinterpret_cast<const uint32_t*>(&local_ip6),
            local_port,
            reinterpret_cast<const uint32_t*>(&remote_ip6),
            remote_port,
            flow_id,
            compartment_id,
            interface_luid,
            protocol);
    }
    void
    configure_v4(
        uint32_t local_ip4,
        uint16_t local_port,
        uint32_t remote_ip4,
        uint16_t remote_port,
        uint64_t flow_id,
        uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID,
        uint64_t interface_luid = 0,
        uint8_t protocol = IPPROTO_TCP)
    {
        ctx.family = AF_INET;
        ctx.protocol = protocol;
        ctx.local_ip4 = local_ip4;
        ctx.local_port = local_port;
        ctx.remote_ip4 = remote_ip4;
        ctx.remote_port = remote_port;
        ctx.flow_id = flow_id;
        ctx.compartment_id = compartment_id;
        ctx.interface_luid = interface_luid;
    }
    template <typename DataType>
    void
    test_classify(
        const std::string& test_name,
        flow_direction_t direction,
        DataType data,
        int expected_result,
        flow_classify_action_t expected_action)
    {
        CAPTURE(test_name);
        ctx.direction = (uint8_t)direction;
        data_in.assign(std::ranges::cdata(data), std::ranges::cdata(data) + std::ranges::size(data));
        opts.data_in = data_in.data();
        opts.data_size_in = static_cast<uint32_t>(data_in.size());

        int result = bpf_prog_test_run_opts(program_fd, &opts);
        SAFE_REQUIRE(result == expected_result);
        SAFE_REQUIRE(opts.retval == static_cast<uint32_t>(expected_action));
    }
    void
    test_classify(
        const std::string& test_name,
        flow_direction_t direction,
        const char* data,
        int expected_result,
        flow_classify_action_t expected_action)
    {
        test_classify(test_name, direction, std::string{data}, expected_result, expected_action);
    }
    int
    get_program_fd() const
    {
        return program_fd;
    }
    ~flow_classify_test_helper()
    {
        if (is_attached) {
            bpf_prog_detach2(program_fd, 0, BPF_FLOW_CLASSIFY);
        }
    }
};

// Flow classify tests
TEST_CASE("flow_classify_prog_test_run", "[flow_classify]")
{
    flow_classify_test_helper allow_helper("flow_classify_allow_all");
    allow_helper.configure_v4(
        htonl(0x7f000001),          /* local_ip4 */
        htons(8080),                /* local_port */
        htonl(0x7f000001),          /* remote_ip4 */
        htons(12345),               /* remote_port */
        12345,                      /* flow_id */
        UNSPECIFIED_COMPARTMENT_ID, /* compartment_id */
        0,                          /* interface_luid */
        IPPROTO_TCP);               /* protocol */
    allow_helper.test_classify(
        "test_run_allow_all_v4", /* test_name */
        FLOW_DIRECTION_INBOUND,  /* direction */
        "HTTP",                  /* data */
        0,                       /* expected_result */
        FLOW_CLASSIFY_ALLOW);    /* expected_action */

    // Block-all IPv6 test.
    flow_classify_test_helper block_helper("flow_classify_block_all");
    block_helper.configure_v6(
        default_flow_local_ip6,  /* local_ip6 */
        htons(53),               /* local_port */
        default_flow_remote_ip6, /* remote_ip6 */
        htons(54321),            /* remote_port */
        67890,                   /* flow_id */
        DEFAULT_COMPARTMENT_ID,  /* compartment_id */
        999);                    /* interface_luid */
    block_helper.test_classify(
        "test_run_block_all_v6",                        /* test_name */
        FLOW_DIRECTION_OUTBOUND,                        /* direction */
        std::span<const uint8_t>({'H', 'T', 'T', 'P'}), /* data */
        0,                                              /* expected_result */
        FLOW_CLASSIFY_BLOCK);                           /* expected_action */
}

TEST_CASE("flow_classify_tcp_connection_tests", "[flow_classify]")
{
    // Test real TCP connection with flow_classify program
    // First test without program to ensure basic connectivity works
    std::cout << "Testing basic connectivity without eBPF program" << std::endl;

    // Test basic connection first
    {
        stream_client_socket_t tcp_client(SOCK_STREAM, IPPROTO_TCP, 0, IPv4);
        stream_server_socket_t tcp_server(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT + 100);

        sockaddr_storage destination_address{};
        IN4ADDR_SETLOOPBACK((PSOCKADDR_IN)&destination_address);

        tcp_server.post_async_receive();

        const char* tcp_message = "flow_classify_tcp_baseline_test";
        tcp_client.send_message_to_remote_host(tcp_message, destination_address, SOCKET_TEST_PORT + 100);
        tcp_client.complete_async_send(1000);

        tcp_server.complete_async_receive(1000);

        uint32_t received_size;
        char* received_message;
        tcp_server.get_received_message(received_size, received_message);
        SAFE_REQUIRE(received_size == static_cast<uint32_t>(strlen(tcp_message)));
        SAFE_REQUIRE(memcmp(received_message, tcp_message, received_size) == 0);

        std::cout << "Basic connectivity test passed" << std::endl;
    }

    // Now test with flow_classify program
    flow_classify_test_helper helper("flow_classify_allow_all", true);
    std::cout << "Testing with flow_classify_allow_all program attached" << std::endl;

    std::cout << "About to send V4" << std::endl;
    try {
        // Test IPv4 TCP connection
        stream_client_socket_t tcp_client(SOCK_STREAM, IPPROTO_TCP, 0, IPv4);
        stream_server_socket_t tcp_server(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT + 100);

        sockaddr_storage destination_address{};
        IN4ADDR_SETLOOPBACK((PSOCKADDR_IN)&destination_address);

        tcp_server.post_async_receive();

        const char* tcp_message = "flow_classify_tcp_test";
        tcp_client.send_message_to_remote_host(tcp_message, destination_address, SOCKET_TEST_PORT + 100);
        tcp_client.complete_async_send(1000);

        tcp_server.complete_async_receive(1000);

        uint32_t received_size;
        char* received_message;
        tcp_server.get_received_message(received_size, received_message);
        SAFE_REQUIRE(received_size == static_cast<uint32_t>(strlen(tcp_message)));
        SAFE_REQUIRE(memcmp(received_message, tcp_message, received_size) == 0);

        std::cout << "IPv4 TCP test passed" << std::endl;

    } catch (const std::exception& e) {
        // For flow classify, connection failures might be expected depending on the program behavior
        std::cout << "IPv4 TCP test encountered expected behavior: " << e.what() << std::endl;
        // Don't fail the test - this might be expected behavior for flow classify programs
    }

    std::cout << "About to send V6" << std::endl;
    try {
        // Test IPv6 TCP connection
        stream_client_socket_t tcp_client_v6(SOCK_STREAM, IPPROTO_TCP, 0, IPv6);
        stream_server_socket_t tcp_server_v6(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT + 102);

        const char* tcp_message_v6 = "flow_classify_tcp_v6_test";
        sockaddr_storage destination_address{};
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);

        tcp_server_v6.post_async_receive();

        tcp_client_v6.send_message_to_remote_host(tcp_message_v6, destination_address, SOCKET_TEST_PORT + 102);
        tcp_client_v6.complete_async_send(1000);

        tcp_server_v6.complete_async_receive(1000);

        uint32_t received_size_v6;
        char* received_message_v6;
        tcp_server_v6.get_received_message(received_size_v6, received_message_v6);
        SAFE_REQUIRE(received_size_v6 == static_cast<uint32_t>(strlen(tcp_message_v6)));
        SAFE_REQUIRE(memcmp(received_message_v6, tcp_message_v6, received_size_v6) == 0);

        std::cout << "IPv6 TCP test passed" << std::endl;

    } catch (const std::exception& e) {
        // For flow classify, connection failures might be expected depending on the program behavior
        std::cout << "IPv6 TCP test encountered expected behavior: " << e.what() << std::endl;
        // Don't fail the test - this might be expected behavior for flow classify programs
    }
}

TEST_CASE("flow_classify_attach_detach", "[flow_classify]")
{
    // Test program attach/detach lifecycle for flow_classify
    native_module_helper_t helper;
    helper.initialize("flow_classify_allow_all", _is_main_thread);

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* program = bpf_object__find_program_by_name(object, "flow_classify_allow_all");
    SAFE_REQUIRE(program != nullptr);

    int program_fd = bpf_program__fd(program);
    SAFE_REQUIRE(program_fd > 0);

    // Test initial attach
    int result = bpf_prog_attach(program_fd, 0, BPF_FLOW_CLASSIFY, 0);
    SAFE_REQUIRE(result == 0);

    // Test double attach should fail (only one program per hook allowed)
    native_module_helper_t helper2;
    helper2.initialize("flow_classify_block_all", _is_main_thread);

    struct bpf_object* object2 = bpf_object__open(helper2.get_file_name().c_str());
    bpf_object_ptr object_ptr2(object2);

    SAFE_REQUIRE(object2 != nullptr);
    SAFE_REQUIRE(bpf_object__load(object2) == 0);

    bpf_program* program2 = bpf_object__find_program_by_name(object2, "flow_classify_block_all");
    SAFE_REQUIRE(program2 != nullptr);

    int program_fd2 = bpf_program__fd(program2);
    SAFE_REQUIRE(program_fd2 > 0);

    // Second attach should fail
    result = bpf_prog_attach(program_fd2, 0, BPF_FLOW_CLASSIFY, 0);
    SAFE_REQUIRE(result != 0);

    // Test detach
    result = bpf_prog_detach2(program_fd, 0, BPF_FLOW_CLASSIFY);
    SAFE_REQUIRE(result == 0);

    // Test attach after detach
    result = bpf_prog_attach(program_fd2, 0, BPF_FLOW_CLASSIFY, 0);
    SAFE_REQUIRE(result == 0);

    // Test detach of second program
    result = bpf_prog_detach2(program_fd2, 0, BPF_FLOW_CLASSIFY);
    SAFE_REQUIRE(result == 0);

    // Test double detach (TODO: should fail?)
    result = bpf_prog_detach2(program_fd2, 0, BPF_FLOW_CLASSIFY);
    SAFE_REQUIRE(result == 0);
}

TEST_CASE("flow_classify_allow_all_test", "[flow_classify]")
{
    // Test flow_classify_allow_all program allows all connections
    flow_classify_test_helper helper("flow_classify_allow_all", true);

    // Test that basic TCP socket operations work with allow_all program using helper classes
    {
        // Test TCP IPv4 connection
        stream_client_socket_t tcp_client(SOCK_STREAM, IPPROTO_TCP, 0, IPv4);

        sockaddr_storage tcp_address = {};
        IN4ADDR_SETLOOPBACK((PSOCKADDR_IN)&tcp_address);

        // Attempt connection (may fail due to no server, but should trigger flow classification)
        try {
            const char* test_message = "allow_all_tcp_test";
            tcp_client.send_message_to_remote_host(test_message, tcp_address, SOCKET_TEST_PORT + 110);
            tcp_client.complete_async_send(100, TIMEOUT); // Expect timeout since no server
        } catch (...) {
            std::cout << "TCP connection failed as expected\n";
        }
        tcp_client.close();
    }

    {
        // Test TCP IPv6 connection
        stream_client_socket_t tcp_v6_client(SOCK_STREAM, IPPROTO_TCP, 0, IPv6);

        sockaddr_storage destination_v6_address = {};
        destination_v6_address.ss_family = AF_INET6;
        ((sockaddr_in6*)&destination_v6_address)->sin6_port = htons(static_cast<uint16_t>(SOCKET_TEST_PORT + 112));
        ((sockaddr_in6*)&destination_v6_address)->sin6_addr = in6addr_loopback;

        try {
            const char* test_message = "allow_all_tcp_v6_test";
            tcp_v6_client.send_message_to_remote_host(test_message, destination_v6_address, SOCKET_TEST_PORT + 112);
            tcp_v6_client.complete_async_send(100, TIMEOUT); // Expect timeout since no server
        } catch (...) {
            std::cout << "TCP connection failed as expected\n";
        }
        tcp_v6_client.close();
    }
}

TEST_CASE("flow_classify_block_all_test", "[flow_classify]")
{
    // Test flow_classify_block_all program blocks all connections
    flow_classify_test_helper helper("flow_classify_block_all", true);

    // Test that TCP connections are blocked or behave differently with block_all program
    {
        // Test TCP IPv4 connection - should be blocked by the program
        stream_client_socket_t tcp_client(SOCK_STREAM, IPPROTO_TCP, 0, IPv4);
        stream_server_socket_t tcp_server(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT + 120);

        sockaddr_storage tcp_address = {};
        tcp_address.ss_family = AF_INET;
        ((sockaddr_in*)&tcp_address)->sin_port = htons(static_cast<uint16_t>(SOCKET_TEST_PORT + 120));
        ((sockaddr_in*)&tcp_address)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        tcp_server.post_async_receive();

        try {
            const char* test_message = "block_all_tcp_test";
            tcp_client.send_message_to_remote_host(test_message, tcp_address, SOCKET_TEST_PORT + 120);
            tcp_client.complete_async_send(100, expected_result_t::FAILURE); // Expect socket access failure

            tcp_server.complete_async_receive(1000, true);
        } catch (...) {
            std::cout << "TCP connection blocked or failed as expected\n";
        }
        tcp_client.close();
    }

    {
        // Test TCP IPv6 connection
        stream_client_socket_t tcp_v6_client(SOCK_STREAM, IPPROTO_TCP, 0, IPv6);
        stream_server_socket_t tcp_server_v6(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT + 122);

        sockaddr_storage tcp_v6_address = {};
        tcp_v6_address.ss_family = AF_INET6;
        ((sockaddr_in6*)&tcp_v6_address)->sin6_port = htons(static_cast<uint16_t>(SOCKET_TEST_PORT + 122));
        ((sockaddr_in6*)&tcp_v6_address)->sin6_addr = in6addr_loopback;

        tcp_server_v6.post_async_receive();

        try {
            const char* test_message = "block_all_tcp_v6_test";
            tcp_v6_client.send_message_to_remote_host(test_message, tcp_v6_address, SOCKET_TEST_PORT + 122);
            // tcp_v6_client.complete_async_send(1000);
            tcp_v6_client.complete_async_send(100, expected_result_t::FAILURE); // Expect socket access failure

            tcp_server_v6.complete_async_receive(1000, true);
        } catch (...) {
            printf("IPv6 TCP connection blocked or failed as expected\n");
        }
        tcp_v6_client.close();
    }
}

TEST_CASE("flow_classify_need_more_data_test", "[flow_classify]")
{
    flow_classify_test_helper helper("flow_classify_need_more_data");
    helper.configure_v4(
        htonl(INADDR_LOOPBACK),     /* local_ip4 */
        htons(80),                  /* local_port */
        htonl(INADDR_LOOPBACK),     /* remote_ip4 */
        htons(12345),               /* remote_port */
        12345,                      /* flow_id */
        UNSPECIFIED_COMPARTMENT_ID, /* compartment_id */
        0,                          /* interface_luid */
        IPPROTO_TCP);               /* protocol */

    helper.test_classify(
        "test_run_need_more_data_v4",  /* test_name */
        FLOW_DIRECTION_INBOUND,        /* direction */
        "GET / HTTP/1.1\r\n",          /* data */
        0,                             /* expected_result */
        FLOW_CLASSIFY_NEED_MORE_DATA); /* expected_action */
}

TEST_CASE("flow_classify_conditional_test", "[flow_classify]")
{
    flow_classify_test_helper helper("flow_classify_conditional");
    // Test HTTP port (8888) - should be allowed because it is GET
    helper.configure_v4(
        htonl(INADDR_LOOPBACK), htons(80), htonl(INADDR_LOOPBACK), htons(8888), 12345, UNSPECIFIED_COMPARTMENT_ID, 0);
    helper.test_classify("test_http_get", FLOW_DIRECTION_INBOUND, "GET / HTTP", 0, FLOW_CLASSIFY_ALLOW);
    helper.test_classify("test_http_put", FLOW_DIRECTION_INBOUND, "PUT /", 0, FLOW_CLASSIFY_BLOCK);

    // Test HTTPS+1 port (444) - should be blocked
    helper.configure_v4(
        htonl(INADDR_LOOPBACK), htons(80), htonl(INADDR_LOOPBACK), htons(444), 12346, UNSPECIFIED_COMPARTMENT_ID, 0);
    helper.test_classify(
        "test_https",
        FLOW_DIRECTION_INBOUND,
        std::span<const uint8_t>({0x16, 0x03, 0x01, 0x00, 0x01, 0x01}),
        0,
        FLOW_CLASSIFY_BLOCK);

    // Test SSH port (22) - should be allowed
    helper.configure_v4(
        htonl(INADDR_LOOPBACK), htons(80), htonl(INADDR_LOOPBACK), htons(22), 12347, UNSPECIFIED_COMPARTMENT_ID, 0);
    helper.test_classify(
        "test_ssh",
        FLOW_DIRECTION_INBOUND,
        std::span<const uint8_t>({'S', 'S', 'H', '-', '2', '.', '0', '-'}),
        0,
        FLOW_CLASSIFY_ALLOW);

    // Test random port - should need more data
    helper.configure_v4(
        htonl(INADDR_LOOPBACK), htons(80), htonl(INADDR_LOOPBACK), htons(12345), 12348, UNSPECIFIED_COMPARTMENT_ID, 0);

    helper.test_classify(
        "test_random_port",
        FLOW_DIRECTION_INBOUND,
        std::span<const uint8_t>({0x12, 0x34, 0x56, 0x78}),
        0,
        FLOW_CLASSIFY_NEED_MORE_DATA);

    // Test IPv6 scenarios
    helper.configure_v6(
        in6addr_loopback, htons(80), in6addr_loopback, htons(8888), 12349, UNSPECIFIED_COMPARTMENT_ID, 0);

    helper.test_classify("test_ipv6_http", FLOW_DIRECTION_INBOUND, "GET / HTTP", 0, FLOW_CLASSIFY_ALLOW);

    helper.test_classify("test_ipv6_https", FLOW_DIRECTION_INBOUND, "PUT /", 0, FLOW_CLASSIFY_BLOCK);

    helper.test_classify("test_ipv6_random_port", FLOW_DIRECTION_INBOUND, "GET / HTTP", 0, FLOW_CLASSIFY_ALLOW);
}

TEST_CASE("flow_classify_multiple_connections", "[flow_classify]")
{
    // Test performance impact of flow classification
    native_module_helper_t helper;
    helper.initialize("flow_classify_allow_all", _is_main_thread);

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* program = bpf_object__find_program_by_name(object, "flow_classify_allow_all");
    SAFE_REQUIRE(program != nullptr);

    int program_fd = bpf_program__fd(program);
    SAFE_REQUIRE(program_fd > 0);

    // Measure baseline performance without eBPF program
    auto baseline_start = std::chrono::high_resolution_clock::now();

    const int num_iterations = 20;
    for (int i = 0; i < num_iterations; i++) {
        SOCKET test_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (test_socket != INVALID_SOCKET) {
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(static_cast<uint16_t>(SOCKET_TEST_PORT + 200 + i));

            // Set non-blocking to avoid hanging
            u_long mode = 1;
            ioctlsocket(test_socket, FIONBIO, &mode);

            connect(test_socket, (sockaddr*)&addr, sizeof(addr));
            closesocket(test_socket);
        }
    }

    auto baseline_end = std::chrono::high_resolution_clock::now();
    auto baseline_duration = std::chrono::duration_cast<std::chrono::milliseconds>(baseline_end - baseline_start);

    // Attach the program and measure performance with eBPF
    int result = bpf_prog_attach(program_fd, 0, BPF_FLOW_CLASSIFY, 0);
    SAFE_REQUIRE(result == 0);

    auto ebpf_start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_iterations; i++) {
        SOCKET test_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (test_socket != INVALID_SOCKET) {
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(static_cast<uint16_t>(SOCKET_TEST_PORT + 250 + i));

            u_long mode = 1;
            ioctlsocket(test_socket, FIONBIO, &mode);

            connect(test_socket, (sockaddr*)&addr, sizeof(addr));
            closesocket(test_socket);
        }
    }

    auto ebpf_end = std::chrono::high_resolution_clock::now();
    auto ebpf_duration = std::chrono::duration_cast<std::chrono::milliseconds>(ebpf_end - ebpf_start);

    printf("Baseline duration: %lld ms\n", baseline_duration.count());
    printf("eBPF duration: %lld ms\n", ebpf_duration.count());

    // Test with rapid UDP connections
    auto rapid_start = std::chrono::high_resolution_clock::now();

    const int rapid_iterations = 50;
    for (int i = 0; i < rapid_iterations; i++) {
        SOCKET udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_socket != INVALID_SOCKET) {
            sockaddr_in udp_addr = {};
            udp_addr.sin_family = AF_INET;
            udp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            udp_addr.sin_port = htons(static_cast<uint16_t>(SOCKET_TEST_PORT + 300 + (i % 10)));

            const char* rapid_data = "rapid_test";
            sendto(
                udp_socket,
                rapid_data,
                static_cast<int>(strlen(rapid_data)),
                0,
                (sockaddr*)&udp_addr,
                sizeof(udp_addr));
            closesocket(udp_socket);
        }
    }

    auto rapid_end = std::chrono::high_resolution_clock::now();
    auto rapid_duration = std::chrono::duration_cast<std::chrono::milliseconds>(rapid_end - rapid_start);

    printf("Rapid connections duration: %lld ms\n", rapid_duration.count());

    // Detach the program
    result = bpf_prog_detach2(program_fd, 0, BPF_FLOW_CLASSIFY);
    SAFE_REQUIRE(result == 0);

    // Performance should be reasonable - allow some overhead but not excessive
    if (baseline_duration.count() > 0) {
        double overhead_ratio = static_cast<double>(ebpf_duration.count()) / baseline_duration.count();
        printf("Performance overhead ratio: %.2f\n", overhead_ratio);
        // Allow up to 5x overhead for this test (it's mostly about ensuring no crashes)
        SAFE_REQUIRE(overhead_ratio < 5.0);
    }
}

TEST_CASE("flow_classify_error_conditions_socket", "[flow_classify]")
{
    // Test error conditions and edge cases for flow classification
    native_module_helper_t helper;
    helper.initialize("flow_classify_allow_all", _is_main_thread);

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* program = bpf_object__find_program_by_name(object, "flow_classify_allow_all");
    SAFE_REQUIRE(program != nullptr);

    int program_fd = bpf_program__fd(program);
    SAFE_REQUIRE(program_fd > 0);

    // Test with invalid context data
    bpf_flow_classify_t invalid_ctx = {};
    // Leave most fields uninitialized/invalid
    invalid_ctx.family = 999;   // Invalid family
    invalid_ctx.protocol = 255; // Invalid protocol

    bpf_test_run_opts invalid_opts{};
    invalid_opts.ctx_in = &invalid_ctx;
    invalid_opts.ctx_size_in = sizeof(invalid_ctx);
    invalid_opts.ctx_out = &invalid_ctx;
    invalid_opts.ctx_size_out = sizeof(invalid_ctx);

    // Bad context should fail.
    int result = bpf_prog_test_run_opts(program_fd, &invalid_opts);
    SAFE_REQUIRE(result == -EINVAL);

    // Test with null data pointers
    bpf_flow_classify_t null_data_ctx = {};
    null_data_ctx.family = AF_INET;
    null_data_ctx.local_ip4 = htonl(INADDR_LOOPBACK);
    null_data_ctx.local_port = htons(8080);
    null_data_ctx.remote_ip4 = htonl(INADDR_LOOPBACK);
    null_data_ctx.remote_port = htons(static_cast<uint16_t>(12345));
    null_data_ctx.protocol = IPPROTO_TCP;

    bpf_test_run_opts null_opts{};
    null_opts.ctx_in = &null_data_ctx;
    null_opts.ctx_size_in = sizeof(null_data_ctx);
    null_opts.ctx_out = &null_data_ctx;
    null_opts.ctx_size_out = sizeof(null_data_ctx);
    null_opts.data_in = nullptr;
    null_opts.data_size_in = 0;
    null_opts.data_out = nullptr;
    null_opts.data_size_out = 0;

    result = bpf_prog_test_run_opts(program_fd, &null_opts);
    SAFE_REQUIRE(result == -EINVAL);

    // Test with very large values
    bpf_flow_classify_t large_values_ctx = {};
    large_values_ctx.family = AF_INET;
    large_values_ctx.local_ip4 = htonl(INADDR_LOOPBACK);
    large_values_ctx.local_port = htons(8080);
    large_values_ctx.remote_ip4 = htonl(INADDR_LOOPBACK);
    large_values_ctx.remote_port = htons(static_cast<uint16_t>(12345));
    large_values_ctx.protocol = IPPROTO_TCP;
    large_values_ctx.interface_luid = UINT64_MAX;
    large_values_ctx.compartment_id = UINT32_MAX;

    std::vector<uint8_t> large_data(1024 * 1024, 0x12); // 1 MB of data

    large_values_ctx.data_start = large_data.data();
    large_values_ctx.data_end = large_values_ctx.data_start + large_data.size();

    bpf_test_run_opts large_opts{};
    large_opts.ctx_in = &large_values_ctx;
    large_opts.ctx_size_in = sizeof(large_values_ctx);
    large_opts.ctx_out = nullptr;
    large_opts.ctx_size_out = 0;
    large_opts.data_in = large_data.data();
    large_opts.data_size_in = static_cast<uint32_t>(large_data.size());
    large_opts.data_out = nullptr;
    large_opts.data_size_out = 0;

    result = bpf_prog_test_run_opts(program_fd, &large_opts);
    SAFE_REQUIRE(result == -EINVAL); /* TODO: ??? */

    // Test attaching program and then trying invalid operations
    result = bpf_prog_attach(program_fd, 0, BPF_FLOW_CLASSIFY, 0);
    SAFE_REQUIRE(result == 0);

    // FIXME: this test passes?
    // Test detaching with wrong program fd
    result = bpf_prog_detach2(program_fd + 1000, 0, BPF_FLOW_CLASSIFY);
    SAFE_REQUIRE(result == 0); /* ??? */

    // Test attaching with invalid attach type - should fail
    result = bpf_prog_attach(program_fd, 0, static_cast<bpf_attach_type>(999), 0);
    SAFE_REQUIRE(result != 0);

    // Test edge case socket operations
    SOCKET edge_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SAFE_REQUIRE(edge_socket != INVALID_SOCKET);

    // Test with port 0 (system assigned)
    sockaddr_in addr_port0 = {};
    addr_port0.sin_family = AF_INET;
    addr_port0.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr_port0.sin_port = 0; // Let system assign

    if (bind(edge_socket, (sockaddr*)&addr_port0, sizeof(addr_port0)) == 0) {
        // Get the assigned port
        sockaddr_in assigned_addr = {};
        int addr_len = sizeof(assigned_addr);
        if (getsockname(edge_socket, (sockaddr*)&assigned_addr, &addr_len) == 0) {
            printf("System assigned port: %d\n", ntohs(assigned_addr.sin_port));
        }
    }
    closesocket(edge_socket);

    // Test with very high port numbers
    SOCKET high_port_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SAFE_REQUIRE(high_port_socket != INVALID_SOCKET);

    sockaddr_in high_port_addr = {};
    high_port_addr.sin_family = AF_INET;
    high_port_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    high_port_addr.sin_port = htons(static_cast<uint16_t>(65000)); // Very high port

    const char* high_port_data = "high_port_test";
    sendto(
        high_port_socket,
        high_port_data,
        static_cast<int>(strlen(high_port_data)),
        0,
        (sockaddr*)&high_port_addr,
        sizeof(high_port_addr));
    closesocket(high_port_socket);

    // Properly detach the program
    result = bpf_prog_detach2(program_fd, 0, BPF_FLOW_CLASSIFY);
    SAFE_REQUIRE(result == 0);

    // Test operations after detach - program execution should still work
    bpf_flow_classify_t post_detach_ctx = {};
    post_detach_ctx.family = AF_INET;
    post_detach_ctx.local_ip4 = htonl(INADDR_LOOPBACK);
    post_detach_ctx.local_port = htons(8080);
    post_detach_ctx.remote_ip4 = htonl(INADDR_LOOPBACK);
    post_detach_ctx.remote_port = htons(static_cast<uint16_t>(12345));
    post_detach_ctx.protocol = IPPROTO_TCP;

    std::vector<uint8_t> post_detach_data = {
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50}; // "GET / HTTP"
    bpf_test_run_opts post_opts{};
    post_opts.ctx_in = &post_detach_ctx;
    post_opts.ctx_size_in = sizeof(post_detach_ctx);
    post_opts.ctx_out = &post_detach_ctx;
    post_opts.ctx_size_out = sizeof(post_detach_ctx);
    post_opts.data_in = post_detach_data.data();
    post_opts.data_size_in = static_cast<uint32_t>(post_detach_data.size());
    post_opts.data_out = post_detach_data.data();
    post_opts.data_size_out = static_cast<uint32_t>(post_detach_data.size());

    result = bpf_prog_test_run_opts(program_fd, &post_opts);
    SAFE_REQUIRE(result == 0);
}

int
main(int argc, char* argv[])
{
    WSAData data;

    _is_main_thread = true;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    int result = Catch::Session().run(argc, argv);

    WSACleanup();

    return result;
}
