# New ebpf Ring Buffer Map (proposal)

## Overview

The current ringbuffer uses a pure callback-based approach to reading the ringbuffer.
Linux also supports memory-mapped polling consumers, which can't be directly supported in the current model.

The new API will support 2 consumer types: callbacks and direct access to the mapped producer memory (with poll to wait for data).

Asynchronous callback consumer:

1. Call `ring_buffer__new` to set up callback with RINGBUF_FLAG_AUTO_CALLBACK specified.
    - Note: automatic callbacks are the current default behavior.
      This may change in the future with #4142 to match the linux behavior so should always be specified.
2. The callback will be invoked for each record written to the ring buffer.

Synchronous callback consumer:

1. Call `ring_buffer__new` to set up callback with RINGBUF_FLAG_NO_AUTO_CALLBACK specified.
2. Call `ring_buffer__poll()` to wait for data if needed and invoke the callback on all available records.

Mapped memory consumer:

1. Call `ebpf_ring_buffer_get_buffer` to get pointers to the mapped producer/consumer pages.
2. Call `ebpf_ring_buffer_get_wait_handle` to get the wait handle.
3. Directly read records from the producer pages (and update consumer offset as we read).
4. Call `WaitForSingleObject`/`WaitForMultipleObject` as needed to wait for new data to be available.

### Differences from linux API

#### Poll and Consume

On linux `ring_buffer__poll()` and `ring_buffer__consume()` are used to invoke the callback.
`poll()` waits for available data (or until timeout), then consume all available records.
`consume()` consumes all available records (without waiting).

Windows will initially only support `ring_buffer__poll()`, which can be called with a timeout of zero
to get the same behaviour as `ring_buffer__consume()`.

#### Asynchronous callbacks

On Linux ring buffers currently support only synchronous callbacks (using poll/consume).
In contrast, Windows eBPF currently supports only asynchronous ring buffer callbacks,
where the callback is automatically invoked when data is available.

This proposal adds support for synchronous consumers by setting the `RINGBUF_FLAG_NO_AUTO_CALLBACK` flag.
With the flag set, callbacks will not automatically be called.
To invoke the callback and `ring_buffer__poll()`
should be called to poll for available data and invoke the callback.
On Windows a timeout of zero can be passed to `ring_buffer__poll()` to get the same behaviour as `ring_buffer__consume()` (consume available records without waiting).

When #4142 is resolved the default behaviour will be changed from asynchronous (automatic) to synchronous callbacks,
so `RINGBUF_FLAG_AUTO_CALLBACK` should always be specified for asynchronous callbacks for forward-compatibility.

#### Memory mapped consumers

As an alternative to callbacks, Linux ring buffer consumers can directly access the
ring buffer data by calling `mmap()` on a ring_buffer map fd to map the data into user space.
`ring_buffer__epoll_fd()` is used (on Linux) to get an fd to use with epoll to wait for data.

Windows doesn't have identical or directly compatible APIs to Linux mmap and epoll, so instead we will perfom the mapping
in the eBPF core and use KEVENTs to signal for new data.

For direct memory mapped consumers on Windows, use `ebpf_ring_buffer_get_buffer` to get pointers to the producer and consumer
pages mapped into user space, and `ebpf_ring_buffer_get_wait_handle()` to get the SynchronizationEvent (auto-reset) KEVENT
to use with `WaitForSingleObject`/`WaitForMultipleObject`.

Similar to the linux memory layout, the first page of the producer and consumer memory is the "producer page" and "consumer page",
which contain the 64 bit producer and consumer offsets as the first 8 bytes.
Only the producer may update the producer offset, and only the consumer may update the consumer offset.

## ebpf-for-windows API Changes

### Changes to ebpf helper functions

```c
/**
 * @brief Output record to ringbuf
 *
 * Note newly added flag values (to specify wakeup options).
 *
 * Wakeup options (flags):
 * - 0 (auto/default): Notify if consumer has caught up.
 * - BPF_RB_FORCE_WAKEUP: Always notify consumer.
 * - BPF_RB_NO_WAKEUP: Never notify consumer.
 *
 */
ebpf_result_t
ebpf_ring_buffer_output(_Inout_ ebpf_ring_buffer_t* ring, _In_reads_bytes_(length) uint8_t* data, size_t length, size_t flags)
```

### Updated libbpf API for callback consumer

The behaviour of these functions will be unchanged.

Use the existing `ring_buffer__new()` to set up automatic callbacks for each record.
Call `ebpf_ring_buffer_get_buffer()` ([New eBPF APIs](#new-ebpf-apis-for-mapped-memory-consumer))
to get direct access to the mapped ringbuffer memory.

```c
struct ring_buffer;

typedef int (*ring_buffer_sample_fn)(_Inout_ void *ctx, _In_reads_bytes_(size) void *data, size_t size);

struct ring_buffer_opts {
  size_t sz; /* size of this struct, for forward/backward compatiblity */
  uint64_t flags; /* ring buffer option flags */
};

// Ring buffer manager options.
// - The default behaviour is currently automatic callbacks, but may change in the future per #4142.
// - Only specify one of AUTO_CALLBACKS or NO_AUTO_CALLBACKS - specifying both is not allowed.
enum ring_buffer_flags {
  RINGBUF_FLAG_AUTO_CALLBACK = (uint64_t)1 << 0 /* Automatically invoke callback for each record */
  RINGBUF_FLAG_NO_AUTO_CALLBACK = (uint64_t)2 << 0 /* Don't automatically invoke callback for each record */
};

#define ring_buffer_opts__last_field sz

/**
 * @brief Creates a new ring buffer manager.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 * @param[in] sample_cb Pointer to ring buffer notification callback function.
 * @param[in] ctx Pointer to sample_cb callback function context.
 * @param[in] opts Ring buffer options.
 *
 * @returns Pointer to ring buffer manager.
 */
struct ring_buffer *
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, _Inout_ void *ctx,
		 _In_ const struct ring_buffer_opts *opts);

/**
 * @brief poll ringbuf for new data
 * Poll for available data and consume records, if any are available.
 *
 * If timeout_ms is zero, poll will not wait but only invoke the callback on records that are ready.
 * If timeout_ms is -1, poll will wait until data is ready (no timeout).
 *
 * This function is only supported when automatic callbacks are disabled (see RINGBUF_FLAG_NO_AUTO_CALLBACK).
 *
 * @param[in] rb Pointer to ring buffer manager.
 * @param[in] timeout_ms maximum time to wait for (in milliseconds).
 *
 * @returns number of records consumed, INT_MAX, or a negative number on error
 */
int ring_buffer__poll(_In_ struct ring_buffer *rb, int timeout_ms);

/**
 * @brief Frees a ring buffer manager.
 *
 * @param[in] rb Pointer to ring buffer manager to be freed.
 */
void ring_buffer__free(_Frees_ptr_opt_ struct ring_buffer *rb);
```

### New ebpf APIs for mapped memory consumer

```c
/**
 * Get pointers to mapped producer and consumer pages.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 * @param[out] producer pointer* to start of read-only mapped producer pages
 * @param[out] consumer pointer* to start of read-write mapped consumer page
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval other An error occurred.
 */
ebpf_result_t ebpf_ring_buffer_get_buffer(fd_t map_fd, _Out_ void **producer, _Out_ void **consumer);

/**
 * Get the wait handle to use with WaitForSingleObject/WaitForMultipleObject.
 *
 * @param[in] map_fd File descriptor to ring buffer map.
 *
 * @returns Wait handle
 */
HANDLE ebpf_ring_buffer_get_wait_handle(fd_t map_fd);
```

### New user-space helpers for memory mapped consumer

```c
/**
 * The below helpers simplify memory-mapped consumer logic
 * by abstracting operations on the producer and consumer offsets.
 */

/**
 * Get pointer to consumer offset from consumer page.
 *
 * @param[in] cons pointer* to start of read-write mapped consumer page
 *
 * @returns Pointer to consumer offset
 */
uint64_t* ebpf_ring_buffer_consumer_offset(void *cons);

/**
 * Get pointer to producer offset from producer page.
 *
 * @param[in] prod pointer* to start of read-only mapped producer pages
 *
 * @returns Pointer to producer offset
 */
volatile const uint64_t* ebpf_ring_buffer_producer_offset(volatile const void *prod);

/**
 * Check whether consumer offset == producer offset.
 *
 * Note that not empty doesn't mean data is ready, just that there are records that have been allocated.
 * You still need to check the locked and discarded bits of the record header to determine if a record is ready.
 *
 * @param[in] cons pointer* to start of read-write mapped consumer page
 * @param[in] prod pointer* to start of read-only mapped producer pages
 *
 * @returns 0 if ring buffer is empty, 1 otherwise
 */
int ebpf_ring_buffer_empty(volatile const void *prod, const void *cons);

/**
 * Clear the ring buffer by flushing all completed and in-progress records.
 *
 * This helper just sets the consumer offset to the producer offset
 *
 * @param[in] prod pointer* to start of read-only mapped producer pages
 * @param[in,out] cons pointer* to start of read-write mapped consumer page
 */
void ebpf_ring_buffer_flush(volatile const void *prod, void *cons);

/**
 * Advance consumer offset to next record (if any)
 *
 * @param[in] prod pointer* to start of read-only mapped producer pages
 * @param[in,out] cons pointer* to start of read-write mapped consumer page
 */
void ebpf_ring_buffer_next_record(volatile const void *prod, void *cons);

/**
 * Get record at current ringbuffer offset.

 * @param[in] prod pointer* to start of read-only mapped producer pages
 * @param[in] cons pointer* to start of read-write mapped consumer page
 *
 * @returns E_SUCCESS (0) if record ready, E_LOCKED if record still locked, E_EMPTY if consumer has caught up.
 */
int ebpf_ring_buffer_get_record(volatile const void *prod, const void *cons, volatile const void** record);

```

## Ringbuffer consumer

### mapped memory consumer example

This consumer directly accesses the records from the producer memory and directly updates the consumer offset to show the logic. Normally user code should use the ring buffer helpers
(see second example below) to simplify the logic.

```c++

//
// == Ringbuf helpers ==
//

// Ring buffer record is 64 bit header + data.
typedef struct _rb_header
{
    //NOTE: bit fields are not portable, so this is just for simpler example code -- the actual code should use bit masking to perform equivalent operations on the header bits, and ReadAcquire to read the header.
    uint8_t locked : 1;
    uint8_t discarded : 1;
    uint32_t length : 30;
    uint32_t offset; // for kernel use (offset of record in pages from start of buffer data area)
} rb_header_t;

typedef struct _rb_record
{
    rb_header_t header;
    uint8_t data[];
} rb_record_t;

/**
 * @brief clear the ringbuffer.
 */
void rb_flush(uint64_t *cons_offset, const uint64_t *prod_offset) {
    WriteRelease64(cons_offset,ReadAcquire64(prod_offset));
}


//
// == mmap/epoll consumer ==
//

void *rb_cons; // Pointer to read/write mapped consumer page with consumer offset.
void *rb_prod; // Pointer to start of read-only producer pages.

// Open ringbuffer.
fd_t map_fd = bpf_obj_get(rb_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

// Initialize wait handle for map.
HANDLE wait_handle = ebpf_ring_buffer_get_wait_handle(map_fd);
if (!wait_handle) {
    // … log error …
    goto Exit;
}

// get pointers to the producer/consumer pages
int err = ebpf_ring_buffer_get_buffer(map_fd, &rb_prod, &rb_cons);

if (err) {
    goto Exit;
}

const uint64_t *prod_offset = (const uint64_t*)rb_prod; // Producer offset ptr (r only).
uint64_t *cons_offset = (uint64_t*)rb_cons; // Consumer offset ptr (r/w mapped).
const uint8_t *rb_data = ((const uint8_t*)rb_prod) + PAGESIZE; // Double-mapped rb data ptr (r only).

uint64_t producer_offset = ReadAcquire64(prod_offset);
uint64_t consumer_offset = ReadNoFence64(cons_offset);
// have_data used to track whether we should wait for notification or just keep reading.
bool have_data = producer_offset > consumer_offset;

void           *lp_ctx = NULL;
OVERLAPPED     *overlapped = NULL;
DWORD          bytesTransferred = 0;

// Now loop until error.
For(;;) {
  if (!have_data) { // Only wait if we have already caught up.
    // Wait for rb to notify -- or we could spin/poll until *prod_offset > *cons_offset.
    DWORD wait_status = WaitForSingleObject(wait_handle, INFINITE);

    if (wait_status != WAIT_OBJECT_0) { // No notification
      uint32_t wait_err = GetLastError();
      if (wait_err == /* terminal error */) {
        // … log error …
        break;
      }
      producer_offset = ReadAcquire64(prod_offset);
      have_data = producer_offset > consumer_offset; // It's possible we still have data.
      if (!have_data) continue;
    } else { // We got notified of new data.
      have_data = true;
    }
  }
  uint64_t remaining = producer_offset - consumer_offset;

  if (remaining == 0) {
    have_data = false; // Caught up to producer.
    continue;
  } else if (remaining < sizeof(rb_header_t)) {
    // Bad record or consumer offset out of alignment.
    // … log error …
    break;
  }

  // Check header flags first, then read/skip data and update offset.
  rb_header_t header = (rb_header_t)(&rb_data[consumer_offset % rb_size]);
  if (header.locked) { // Next record not ready yet, wait.
    have_data = false;
    continue;
    // Or we could spin/poll on ((rb_header_t*)(&rb_data[consumer_offset % rb_size]))->locked.
  }
  if (!header.discarded) {
    const rb_record_t *record = *(const rb_record_t*)(&rb_data[consumer_offset % rb_size]);
    // Read data from record->data[0 ... record->length-1].
    // … business logic …
  } // Else it was discarded, skip and continue.

  // Update consumer offset (and pad record length to multiple of 8).
  consumer_offset += sizeof(rb_header_t) + (record->length + 7 & ~7);
  WriteNoFence64(cons_offset,consumer_offset);
}

Exit:
```

### Simplified polling ringbuf consumer

This consumer uses the helpers to consume the ring buffer.

```c
// Initialize wait handle for map.
HANDLE wait_handle = ebpf_ring_buffer_get_wait_handle(map_fd);
if (!wait_handle) {
    // … log error …
    goto Exit;
}

uint32_t wait_err = 0;

// Consumer loop.
for(;;) {
  for(; !(err=ebpf_ring_buffer_get_record(prod,cons,&record)); ebpf_ring_buffer_next_record(prod,cons)) {
    // Data is now in record->data[0 ... record->length-1].
    // … Do record handling here …
  }
  // 3 cases for err:
  // 1) Ringbuf empty - Wait on handle, or poll for !ebpf_ring_buffer_empty(prod,cons).
  // 2) Record locked - Wait on handle, or spin/poll on header lock bit.
  // 3) Corrupt record or consumer offset - Break (could flush to continue reading from next good record).
  if (err!=E_EMPTY && err!=E_LOCKED) {
    // … log error …
    break;
  }
  DWORD wait_status = WaitForSingleObject(wait_handle, INFINITE);

  if (wait_status != WAIT_OBJECT_0) { // No notification
    wait_err = GetLastError();
    if (wait_err == /* terminal error */) {
      // … log error …
      break;
    }
  }
}

```

### Polling ring buffer consumer (linux-style)

```c
// sample callback
int ring_buffer_sample_fn(void *ctx, void *data, size_t size) {
  // … business logic to handle record …
}

// consumer code
struct ring_buffer_opts opts;
opts.sz = sizeof(opts);
opts.flags = RINGBUF_FLAG_NO_AUTO_CALLBACK; //no automatic callbacks

fd_t map_fd = bpf_obj_get(rb_map_name.c_str());
if (map_fd == ebpf_fd_invalid) return 1;

struct ring_buffer *rb = ring_buffer__new(map_fd, ring_buffer_sample_fn sample_cb, NULL);
if (rb == NULL) return 1;

// now loop as long as there isn't an error
while(ring_buffer__poll(rb, -1) >= 0) {
  // data processed by event callback
}

ring_buffer__free(rb);
```