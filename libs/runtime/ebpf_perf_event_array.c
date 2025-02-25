// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_perf_event_array.h"
// #include "ebpf_perf_event_array_record.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_perf_ring
{
    ebpf_ring_buffer_t ring;
    volatile size_t lost_records;
    uint64_t pad;
} ebpf_perf_ring_t;
typedef struct _ebpf_perf_event_array
{
    uint32_t ring_count;
    uint32_t pad1;
    uint64_t pad2[7];
    ebpf_perf_ring_t rings[1];
} ebpf_perf_event_array_t;

static_assert(sizeof(ebpf_perf_ring_t) % EBPF_CACHE_LINE_SIZE == 0, "ebpf_perf_ring_t is not cache aligned.");
static_assert(
    sizeof(ebpf_perf_event_array_t) % EBPF_CACHE_LINE_SIZE == 0, "ebpf_perf_event_array_t is not cache aligned.");

/**
 * @brief Reserve a buffer in the ring buffer from a single exclusive producer.
 * Buffer is valid until either ebpf_ring_buffer_submit, ebpf_ring_buffer_discard, or the end of the current epoch.
 *
 * @note This functions must only be called by a single thread at a time (with exclusive access).
 * With multiple producers should either be locked or written at dispatch to a per-cpu buffer.
 *
 * It is safe to alternate between exclusive and shared reserves as long exclusive reserve is mututally exclusive
 * with any exclusive or shared reserve. A single consumer may still be concurrently reading.
 *
 * @param[in, out] ring_buffer Ring buffer to update.
 * @param[out] data Pointer to start of reserved buffer on success.
 * @param[in] length Length of buffer to reserve.
 * @retval EBPF_SUCCESS Successfully reserved space in the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to reserve space in the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_exclusive_reserve(
    _Inout_ ebpf_ring_buffer_t* ring_buffer, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length);

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_exclusive_reserve(
    _Inout_ ebpf_ring_buffer_t* ring, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length)
{
    return ebpf_ring_buffer_reserve(ring, data, length);
    // // This function will be added to ebpf_ring_buffer.h/c after PR #4204 is merged.
    // //  Exclusive Reserve notes:
    // //  - This function must only be called by a single thread at a time (exclusive access).
    // //    - A single consumer can be concurrently reading.
    // //  - Synchronization:
    // //    - producer_offset WriteRelease ensures record is locked before producer offset is updated.
    // //    - With only a single producer we don't need the loop and can directly update the producer offset.
    // //if (length > _ring_get_length(ring) || length == 0 || length > UINT32_MAX) {
    // if (length > _ring_get_length(ring) || length == 0 || length > UINT32_MAX) {
    //     return EBPF_INVALID_ARGUMENT;
    // }
    // size_t record_size = _ring_record_size(length);
    // size_t consumer_offset = ReadULong64NoFence(&ring->consumer_offset);
    // size_t producer_offset = ReadULong64Acquire(&ring->producer_offset);
    // size_t used_capacity = producer_offset - consumer_offset;
    // if (used_capacity + record_size >= _ring_get_length(ring)) {
    //     return EBPF_NO_MEMORY;
    // }
    // size_t new_producer_offset = producer_offset + record_size;

    // // Update reserve offset (not used for exclusive reserve, but allows switching between exclusive and shared).
    // WriteULong64NoFence(&ring->producer_reserve_offset, new_producer_offset);

    // // Initialize record.
    // ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, producer_offset);
    // _ring_record_initialize(record, (uint32_t)length);
    // // Release producer offset to ensure ordering with setting the lock bit in initialize above.
    // WriteULong64Release(&ring->producer_offset, new_producer_offset);

    // *data = record->data;
    // return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_initialize_ring(
    _Out_writes_bytes_(sizeof(ebpf_ring_buffer_t)) ebpf_ring_buffer_t* ring, size_t capacity)
{
    if ((capacity & ~(capacity - 1)) != capacity) {
        return EBPF_INVALID_ARGUMENT;
    }

    ring->ring_descriptor = ebpf_allocate_ring_buffer_memory(capacity);
    if (!ring->ring_descriptor) {
        return EBPF_NO_MEMORY;
    }
    ring->shared_buffer = ebpf_ring_descriptor_get_base_address(ring->ring_descriptor);
    ring->length = capacity;

    return EBPF_SUCCESS;
}

void
ebpf_ring_buffer_free_ring(_Frees_ptr_opt_ ebpf_ring_buffer_t* ring)
{
    ebpf_free_ring_buffer_memory(ring->ring_descriptor);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_create(
    _Outptr_ ebpf_perf_event_array_t** perf_event_array, size_t capacity, _In_ ebpf_perf_event_array_opts_t* opts)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(opts);
    ebpf_result_t result;
    ebpf_perf_event_array_t* local_perf_event_array = NULL;
    uint32_t ring_count = ebpf_get_cpu_count();
    size_t total_size = sizeof(ebpf_perf_event_array_t) + sizeof(ebpf_perf_ring_t) * (ring_count - 1);

    local_perf_event_array = ebpf_epoch_allocate_with_tag(total_size, EBPF_POOL_TAG_RING_BUFFER);
    if (!local_perf_event_array) {
        result = EBPF_NO_MEMORY;
        goto Error;
    }
    local_perf_event_array->ring_count = ring_count;

    for (uint32_t i = 0; i < ring_count; i++) {
        ebpf_perf_ring_t* ring = &local_perf_event_array->rings[i];
        ebpf_ring_buffer_initialize_ring(&ring->ring, capacity);
        ring->lost_records = 0;
    }

    *perf_event_array = local_perf_event_array;
    local_perf_event_array = NULL;
    return EBPF_SUCCESS;

Error:
    ebpf_perf_event_array_destroy(local_perf_event_array);
    EBPF_RETURN_RESULT(result);
}

void
ebpf_perf_event_array_destroy(_Frees_ptr_opt_ ebpf_perf_event_array_t* perf_event_array)
{
    if (perf_event_array) {
        EBPF_LOG_ENTRY();
        uint32_t ring_count = perf_event_array->ring_count;
        for (uint32_t i = 0; i < ring_count; i++) {
            ebpf_ring_buffer_free_ring(&perf_event_array->rings[i].ring);
        }
        ebpf_epoch_free(perf_event_array);
        EBPF_RETURN_VOID();
    }
}

// In ebpf_platform.h after ringbuf refactor PR #4204 merges.
void
ebpf_lower_irql_from_dispatch_if_needed(KIRQL irql_at_enter)
{
    if (irql_at_enter < DISPATCH_LEVEL) {
        ebpf_lower_irql(irql_at_enter);
    }
}

_Must_inspect_result_ ebpf_result_t
_ebpf_perf_event_array_output(
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint32_t target_cpu,
    _In_reads_bytes_(length) const uint8_t* data,
    size_t length,
    _In_reads_bytes_(extra_length) const uint8_t* extra_data,
    size_t extra_length,
    uint32_t* cpu_id)
{

    KIRQL irql_at_enter = KeGetCurrentIrql();
    if (irql_at_enter < DISPATCH_LEVEL) {
        if (target_cpu != EBPF_MAP_FLAG_CURRENT_CPU) {
            return EBPF_INVALID_ARGUMENT;
        }
        irql_at_enter = ebpf_raise_irql(DISPATCH_LEVEL);
    }

    ebpf_result_t result;
    uint32_t current_cpu = ebpf_get_current_cpu();

    uint32_t _cpu_id = target_cpu;
    if (target_cpu == EBPF_MAP_FLAG_CURRENT_CPU) {
        _cpu_id = current_cpu;
    } else if (_cpu_id != current_cpu) {
        // We only support writes to the current CPU.
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (cpu_id != NULL) {
        *cpu_id = _cpu_id; // return the cpu we are writing to.
    }

    uint8_t* record;
    ebpf_perf_ring_t* ring = &perf_event_array->rings[_cpu_id];

    result = ebpf_ring_buffer_exclusive_reserve(&ring->ring, &record, length + extra_length);
    if (result != EBPF_SUCCESS) {
        ring->lost_records++;
        goto Done;
    }
    memcpy(record, data, length);
    if (extra_data != NULL) {
        memcpy(record + length, extra_data, extra_length);
    }
    result = ebpf_ring_buffer_submit(record);

Done:
    ebpf_lower_irql_from_dispatch_if_needed(irql_at_enter);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output_simple(
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint32_t cpu_id,
    _In_reads_bytes_(length) uint8_t* data,
    size_t length)
{
    return _ebpf_perf_event_array_output(perf_event_array, cpu_id, data, length, NULL, 0, NULL);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output(
    _In_ void* ctx,
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint64_t flags,
    _In_reads_bytes_(length) uint8_t* data,
    size_t length,
    _Out_opt_ uint32_t* cpu_id)
{
    uint32_t _cpu_id = (flags & EBPF_MAP_FLAG_INDEX_MASK) >> EBPF_MAP_FLAG_INDEX_SHIFT;
    uint32_t capture_length = (uint32_t)((flags & EBPF_MAP_FLAG_CTXLEN_MASK) >> EBPF_MAP_FLAG_CTXLEN_SHIFT);

    const void* extra_data = NULL;
    size_t extra_length = 0;
    if (capture_length != 0) {
        // Caller requested data capture.
        ebpf_assert(ctx != NULL);

        uint8_t *ctx_data_start, *ctx_data_end;
        ebpf_program_get_context_data(ctx, &ctx_data_start, &ctx_data_end);

        if (ctx_data_start == NULL || ctx_data_end == NULL) {
            // No context data pointer.
            return EBPF_OPERATION_NOT_SUPPORTED;
        } else if ((uint64_t)(ctx_data_end - ctx_data_start) < (uint64_t)capture_length) {
            // Requested capture length larger than data.
            return EBPF_INVALID_ARGUMENT;
        }

        extra_data = ctx_data_start;
        extra_length = capture_length;
    }
    return _ebpf_perf_event_array_output(perf_event_array, _cpu_id, data, length, extra_data, extra_length, cpu_id);
}

uint32_t
ebpf_perf_event_array_get_ring_count(_In_ const ebpf_perf_event_array_t* perf_event_array)
{
    return perf_event_array->ring_count;
}

size_t
ebpf_perf_event_array_get_lost_count(_In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    return perf_event_array->rings[cpu_id].lost_records;
}

void
ebpf_perf_event_array_query(
    _In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    ebpf_ring_buffer_query(&perf_event_array->rings[cpu_id].ring, consumer, producer);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_return_buffer(
    _Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t consumer_offset)
{
    // Correct command below (for after ringbuf refactor merges).
    return ebpf_ring_buffer_return(&perf_event_array->rings[cpu_id].ring, consumer_offset);
    // return ebpf_ring_buffer_return_buffer(&perf_event_array->rings[cpu_id].ring, consumer_offset);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_map_buffer(
    _In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Outptr_ uint8_t** buffer)
{
    const ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    return ebpf_ring_buffer_map_buffer(&ring->ring, buffer);
}