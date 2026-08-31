// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map_in_map_all_types.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table map_in_map_all_types##_metadata_table

static GUID _bpf2c_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                             0xc847aac8,
                             0xa6f2,
                             0x4b53,
                             {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};
static NPI_MODULEID _bpf2c_module_id = {sizeof(_bpf2c_module_id), MIT_GUID, {0}};
static HANDLE _bpf2c_nmr_client_handle;
static HANDLE _bpf2c_nmr_provider_handle;
extern metadata_table_t metadata_table;

static NTSTATUS
_bpf2c_npi_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance);

static NTSTATUS
_bpf2c_npi_client_detach_provider(_In_ void* client_binding_context);

static const NPI_CLIENT_CHARACTERISTICS _bpf2c_npi_client_characteristics = {
    0,                                  // Version
    sizeof(NPI_CLIENT_CHARACTERISTICS), // Length
    _bpf2c_npi_client_attach_provider,
    _bpf2c_npi_client_detach_provider,
    NULL,
    {0,                                 // Version
     sizeof(NPI_REGISTRATION_INSTANCE), // Length
     &_bpf2c_npi_id,
     &_bpf2c_module_id,
     0,
     NULL}};

static NTSTATUS
_bpf2c_query_npi_module_id(
    _In_ const wchar_t* value_name,
    unsigned long value_type,
    _In_ const void* value_data,
    unsigned long value_length,
    _Inout_ void* context,
    _Inout_ void* entry_context)
{
    UNREFERENCED_PARAMETER(value_name);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(entry_context);

    if (value_type != REG_BINARY) {
        return STATUS_INVALID_PARAMETER;
    }
    if (value_length != sizeof(_bpf2c_module_id.Guid)) {
        return STATUS_INVALID_PARAMETER;
    }

    memcpy(&_bpf2c_module_id.Guid, value_data, value_length);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    RTL_QUERY_REGISTRY_TABLE query_table[] = {
        {
            NULL,                      // Query routine
            RTL_QUERY_REGISTRY_SUBKEY, // Flags
            L"Parameters",             // Name
            NULL,                      // Entry context
            REG_NONE,                  // Default type
            NULL,                      // Default data
            0,                         // Default length
        },
        {
            _bpf2c_query_npi_module_id,  // Query routine
            RTL_QUERY_REGISTRY_REQUIRED, // Flags
            L"NpiModuleId",              // Name
            NULL,                        // Entry context
            REG_NONE,                    // Default type
            NULL,                        // Default data
            0,                           // Default length
        },
        {0}};

    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, registry_path->Buffer, query_table, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = NmrRegisterClient(&_bpf2c_npi_client_characteristics, NULL, &_bpf2c_nmr_client_handle);

Exit:
    if (NT_SUCCESS(status)) {
        driver_object->DriverUnload = DriverUnload;
    }

    return status;
}

void
DriverUnload(_In_ DRIVER_OBJECT* driver_object)
{
    NTSTATUS status = NmrDeregisterClient(_bpf2c_nmr_client_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForClientDeregisterComplete(_bpf2c_nmr_client_handle);
    }
    UNREFERENCED_PARAMETER(driver_object);
}

static NTSTATUS
_bpf2c_npi_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    NTSTATUS status = STATUS_SUCCESS;
    void* provider_binding_context = NULL;
    void* provider_dispatch_table = NULL;

    UNREFERENCED_PARAMETER(client_context);
    UNREFERENCED_PARAMETER(provider_registration_instance);

    if (_bpf2c_nmr_provider_handle != NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = NmrClientAttachProvider(
        nmr_binding_handle, client_context, &metadata_table, &provider_binding_context, &provider_dispatch_table);
    if (status != STATUS_SUCCESS) {
        goto Done;
    }
    _bpf2c_nmr_provider_handle = nmr_binding_handle;

Done:
    return status;
}

static NTSTATUS
_bpf2c_npi_client_detach_provider(_In_ void* client_binding_context)
{
    _bpf2c_nmr_provider_handle = NULL;
    UNREFERENCED_PARAMETER(client_binding_context);
    return STATUS_SUCCESS;
}

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {
     {0, 0},
     {
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         10,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "inner_hash_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         16,                         // Identifier for a map template.
         10,                         // The id of the inner map template.
     },
     "outer_hash_aom"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         20,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "inner_array_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         24,                         // Identifier for a map template.
         20,                         // The id of the inner map template.
     },
     "outer_array_aom"},
    {
     {0, 0},
     {
         1,                     // Current Version.
         80,                    // Struct size up to the last field.
         80,                    // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         4,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         28,                    // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "inner_lru_hash_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         32,                         // Identifier for a map template.
         28,                         // The id of the inner map template.
     },
     "outer_lru_hash_aom"},
    {
     {0, 0},
     {
         1,                     // Current Version.
         80,                    // Struct size up to the last field.
         80,                    // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LPM_TRIE, // Type of map.
         8,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         39,                    // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "inner_lpm_trie_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         43,                         // Identifier for a map template.
         39,                         // The id of the inner map template.
     },
     "outer_lpm_trie_aom"},
    {
     {0, 0},
     {
         1,                        // Current Version.
         80,                       // Struct size up to the last field.
         80,                       // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_HASH, // Type of map.
         4,                        // Size in bytes of a map key.
         4,                        // Size in bytes of a map value.
         10,                       // Maximum number of entries allowed in the map.
         0,                        // Inner map index.
         LIBBPF_PIN_NONE,          // Pinning type for the map.
         47,                       // Identifier for a map template.
         0,                        // The id of the inner map template.
     },
     "inner_percpu_hash_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         51,                         // Identifier for a map template.
         47,                         // The id of the inner map template.
     },
     "outer_percpu_hash_aom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_ARRAY, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         55,                        // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "inner_percpu_array_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         59,                         // Identifier for a map template.
         55,                         // The id of the inner map template.
     },
     "outer_percpu_array_aom"},
    {
     {0, 0},
     {
         1,                            // Current Version.
         80,                           // Struct size up to the last field.
         80,                           // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_PERCPU_HASH, // Type of map.
         4,                            // Size in bytes of a map key.
         4,                            // Size in bytes of a map value.
         10,                           // Maximum number of entries allowed in the map.
         0,                            // Inner map index.
         LIBBPF_PIN_NONE,              // Pinning type for the map.
         63,                           // Identifier for a map template.
         0,                            // The id of the inner map template.
     },
     "inner_lru_percpu_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         67,                         // Identifier for a map template.
         63,                         // The id of the inner map template.
     },
     "outer_lru_percpu_aom"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_QUEUE, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         69,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "inner_queue_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         73,                         // Identifier for a map template.
         69,                         // The id of the inner map template.
     },
     "outer_queue_aom"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_STACK, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         77,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "inner_stack_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         81,                         // Identifier for a map template.
         77,                         // The id of the inner map template.
     },
     "outer_stack_aom"},
    {
     {0, 0},
     {
         1,                    // Current Version.
         80,                   // Struct size up to the last field.
         80,                   // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         8192,                 // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         LIBBPF_PIN_NONE,      // Pinning type for the map.
         87,                   // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "inner_ringbuf_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         91,                         // Identifier for a map template.
         87,                         // The id of the inner map template.
     },
     "outer_ringbuf_aom"},
    {
     {0, 0},
     {
         1,                             // Current Version.
         80,                            // Struct size up to the last field.
         80,                            // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERF_EVENT_ARRAY, // Type of map.
         0,                             // Size in bytes of a map key.
         0,                             // Size in bytes of a map value.
         8192,                          // Maximum number of entries allowed in the map.
         0,                             // Inner map index.
         LIBBPF_PIN_NONE,               // Pinning type for the map.
         95,                            // Identifier for a map template.
         0,                             // The id of the inner map template.
     },
     "inner_perf_aom"},
    {
     {0, 0},
     {
         1,                          // Current Version.
         80,                         // Struct size up to the last field.
         80,                         // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY_OF_MAPS, // Type of map.
         4,                          // Size in bytes of a map key.
         4,                          // Size in bytes of a map value.
         1,                          // Maximum number of entries allowed in the map.
         0,                          // Inner map index.
         LIBBPF_PIN_NONE,            // Pinning type for the map.
         99,                         // Identifier for a map template.
         95,                         // The id of the inner map template.
     },
     "outer_perf_aom"},
    {
     {0, 0},
     {
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         101,               // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "inner_hash_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         107,                       // Identifier for a map template.
         101,                       // The id of the inner map template.
     },
     "outer_hash_hom"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         109,                // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "inner_array_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         113,                       // Identifier for a map template.
         109,                       // The id of the inner map template.
     },
     "outer_array_hom"},
    {
     {0, 0},
     {
         1,                     // Current Version.
         80,                    // Struct size up to the last field.
         80,                    // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         4,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         115,                   // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "inner_lru_hash_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         119,                       // Identifier for a map template.
         115,                       // The id of the inner map template.
     },
     "outer_lru_hash_hom"},
    {
     {0, 0},
     {
         1,                     // Current Version.
         80,                    // Struct size up to the last field.
         80,                    // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LPM_TRIE, // Type of map.
         8,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         121,                   // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "inner_lpm_trie_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         125,                       // Identifier for a map template.
         121,                       // The id of the inner map template.
     },
     "outer_lpm_trie_hom"},
    {
     {0, 0},
     {
         1,                        // Current Version.
         80,                       // Struct size up to the last field.
         80,                       // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_HASH, // Type of map.
         4,                        // Size in bytes of a map key.
         4,                        // Size in bytes of a map value.
         10,                       // Maximum number of entries allowed in the map.
         0,                        // Inner map index.
         LIBBPF_PIN_NONE,          // Pinning type for the map.
         127,                      // Identifier for a map template.
         0,                        // The id of the inner map template.
     },
     "inner_percpu_hash_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         131,                       // Identifier for a map template.
         127,                       // The id of the inner map template.
     },
     "outer_percpu_hash_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_ARRAY, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         133,                       // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "inner_percpu_array_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         137,                       // Identifier for a map template.
         133,                       // The id of the inner map template.
     },
     "outer_percpu_array_hom"},
    {
     {0, 0},
     {
         1,                            // Current Version.
         80,                           // Struct size up to the last field.
         80,                           // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_PERCPU_HASH, // Type of map.
         4,                            // Size in bytes of a map key.
         4,                            // Size in bytes of a map value.
         10,                           // Maximum number of entries allowed in the map.
         0,                            // Inner map index.
         LIBBPF_PIN_NONE,              // Pinning type for the map.
         139,                          // Identifier for a map template.
         0,                            // The id of the inner map template.
     },
     "inner_lru_percpu_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         143,                       // Identifier for a map template.
         139,                       // The id of the inner map template.
     },
     "outer_lru_percpu_hom"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_QUEUE, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         145,                // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "inner_queue_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         149,                       // Identifier for a map template.
         145,                       // The id of the inner map template.
     },
     "outer_queue_hom"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_STACK, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         151,                // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "inner_stack_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         155,                       // Identifier for a map template.
         151,                       // The id of the inner map template.
     },
     "outer_stack_hom"},
    {
     {0, 0},
     {
         1,                    // Current Version.
         80,                   // Struct size up to the last field.
         80,                   // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         8192,                 // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         LIBBPF_PIN_NONE,      // Pinning type for the map.
         157,                  // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "inner_ringbuf_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         161,                       // Identifier for a map template.
         157,                       // The id of the inner map template.
     },
     "outer_ringbuf_hom"},
    {
     {0, 0},
     {
         1,                             // Current Version.
         80,                            // Struct size up to the last field.
         80,                            // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERF_EVENT_ARRAY, // Type of map.
         0,                             // Size in bytes of a map key.
         0,                             // Size in bytes of a map value.
         8192,                          // Maximum number of entries allowed in the map.
         0,                             // Inner map index.
         LIBBPF_PIN_NONE,               // Pinning type for the map.
         163,                           // Identifier for a map template.
         0,                             // The id of the inner map template.
     },
     "inner_perf_hom"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         167,                       // Identifier for a map template.
         163,                       // The id of the inner map template.
     },
     "outer_perf_hom"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         22,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         173,                // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "results"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 45;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t array_of_maps_all_types_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     16,
     "helper_id_16",
    },
    {
     {1, 40, 40}, // Version header.
     11,
     "helper_id_11",
    },
    {
     {1, 40, 40}, // Version header.
     32,
     "helper_id_32",
    },
};

static GUID array_of_maps_all_types_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID array_of_maps_all_types_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t array_of_maps_all_types_maps[] = {
    1,
    3,
    5,
    7,
    9,
    11,
    13,
    15,
    17,
    19,
    21,
    44,
};

#pragma code_seg(push, "sample~2")
static uint64_t
array_of_maps_all_types(void* context, const program_runtime_context_t* runtime_context)
#line 243 "sample/undocked/map_in_map_all_types.c"
{
#line 243 "sample/undocked/map_in_map_all_types.c"
    // Prologue.
#line 243 "sample/undocked/map_in_map_all_types.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r0 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r1 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r2 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r3 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r4 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r5 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r6 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r7 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r8 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r9 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r10 = 0;

#line 243 "sample/undocked/map_in_map_all_types.c"
    r1 = (uintptr_t)context;
#line 243 "sample/undocked/map_in_map_all_types.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 243 "sample/undocked/map_in_map_all_types.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 243 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-8 imm=0
#line 245 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 245 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-8
#line 245 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=8 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=10 dst=r1 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=12 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_1;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=13 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=14 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=16 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=20 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_1;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=21 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
label_1:
    // EBPF_OP_STXW pc=22 dst=r10 src=r1 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_STXW pc=23 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=24 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=26 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=27 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=28 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=30 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_REG pc=32 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=33 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=34 dst=r1 src=r1 offset=0 imm=4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_CALL pc=36 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=37 dst=r0 src=r0 offset=10 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_2;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=38 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=39 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=40 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=41 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=43 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=44 dst=r7 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=46 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_2;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=47 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r7, r0, OFFSET(0));
label_2:
    // EBPF_OP_MOV64_IMM pc=48 dst=r1 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=49 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=50 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=51 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=52 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=53 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=55 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=57 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=58 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_REG pc=59 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=60 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=61 dst=r1 src=r1 offset=0 imm=6
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=64 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=68 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_3;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=69 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=70 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=71 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=72 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=73 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=76 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_3;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=77 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
label_3:
    // EBPF_OP_MOV64_IMM pc=78 dst=r2 src=r0 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=79 dst=r10 src=r2 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-16));
    // EBPF_OP_STXW pc=80 dst=r10 src=r1 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=81 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=82 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=83 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=84 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=85 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=87 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=88 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_REG pc=89 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=90 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=91 dst=r1 src=r1 offset=0 imm=8
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=93 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=94 dst=r0 src=r0 offset=11 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_4;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDDW pc=95 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)720575944674246688;
    // EBPF_OP_STXDW pc=97 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=98 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=99 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=100 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=102 dst=r7 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=104 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_4;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=105 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r7, r0, OFFSET(0));
label_4:
    // EBPF_OP_MOV64_IMM pc=106 dst=r1 src=r0 offset=0 imm=3
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=107 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=108 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=109 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=110 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=111 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=112 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=113 dst=r9 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=114 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=116 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=117 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[9].address);
    // EBPF_OP_MOV64_REG pc=118 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=119 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=120 dst=r1 src=r1 offset=0 imm=10
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[9].address);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=123 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=125 dst=r8 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=127 dst=r0 src=r0 offset=12 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_5;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=128 dst=r10 src=r9 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-16));
    // EBPF_OP_MOV64_IMM pc=129 dst=r8 src=r0 offset=0 imm=1515847684
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(1515847684);
    // EBPF_OP_STXW pc=130 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=131 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=132 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=133 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=134 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=135 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=136 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=137 dst=r0 src=r0 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=138 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_5;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=139 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = r0;
label_5:
    // EBPF_OP_MOV64_IMM pc=140 dst=r1 src=r0 offset=0 imm=4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=141 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=142 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=143 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=144 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=145 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=146 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=147 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=148 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=150 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=151 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[11].address);
    // EBPF_OP_MOV64_REG pc=152 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=153 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=154 dst=r1 src=r1 offset=0 imm=12
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[11].address);
    // EBPF_OP_CALL pc=156 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=157 dst=r0 src=r0 offset=12 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_6;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=158 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_IMM pc=159 dst=r7 src=r0 offset=0 imm=1515847685
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847685);
    // EBPF_OP_STXW pc=160 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=161 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=162 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=163 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=164 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=165 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=166 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=167 dst=r0 src=r0 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=168 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_6;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=169 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_6:
    // EBPF_OP_MOV64_IMM pc=170 dst=r1 src=r0 offset=0 imm=5
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=171 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=172 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=173 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=174 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=175 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=176 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=177 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=179 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=180 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[13].address);
    // EBPF_OP_MOV64_REG pc=181 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=182 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=183 dst=r1 src=r1 offset=0 imm=14
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[13].address);
    // EBPF_OP_CALL pc=185 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=186 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=188 dst=r8 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=190 dst=r0 src=r0 offset=12 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_7;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=191 dst=r10 src=r9 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-16));
    // EBPF_OP_MOV64_IMM pc=192 dst=r8 src=r0 offset=0 imm=1515847686
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(1515847686);
    // EBPF_OP_STXW pc=193 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=194 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=195 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=196 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=197 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=198 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=199 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=200 dst=r0 src=r0 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=201 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_7;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=202 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = r0;
label_7:
    // EBPF_OP_MOV64_IMM pc=203 dst=r1 src=r0 offset=0 imm=6
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=204 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=205 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=206 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=207 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=208 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=209 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=210 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=212 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=213 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[15].address);
    // EBPF_OP_MOV64_REG pc=214 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=215 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=216 dst=r1 src=r1 offset=0 imm=16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[15].address);
    // EBPF_OP_CALL pc=218 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=219 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_8;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=220 dst=r7 src=r0 offset=0 imm=1515847687
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847687);
    // EBPF_OP_STXW pc=221 dst=r10 src=r7 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=222 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=223 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=224 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=225 dst=r3 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=226 dst=r0 src=r0 offset=0 imm=16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=227 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_8;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=228 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_8:
    // EBPF_OP_MOV64_IMM pc=229 dst=r1 src=r0 offset=0 imm=7
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=230 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=231 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=232 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=233 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=234 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=235 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=236 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=238 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=239 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[17].address);
    // EBPF_OP_MOV64_REG pc=240 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=241 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=242 dst=r1 src=r1 offset=0 imm=18
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[17].address);
    // EBPF_OP_CALL pc=244 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=245 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=247 dst=r8 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=249 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_9;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=250 dst=r8 src=r0 offset=0 imm=1515847688
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(1515847688);
    // EBPF_OP_STXW pc=251 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=254 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=255 dst=r3 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=256 dst=r0 src=r0 offset=0 imm=16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=257 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_9;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=258 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = r0;
label_9:
    // EBPF_OP_MOV64_IMM pc=259 dst=r1 src=r0 offset=0 imm=8
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=260 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=261 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=262 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=263 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=264 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=265 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=266 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=268 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=269 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[19].address);
    // EBPF_OP_MOV64_REG pc=270 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=271 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=272 dst=r1 src=r1 offset=0 imm=20
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[19].address);
    // EBPF_OP_CALL pc=274 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=275 dst=r0 src=r0 offset=13 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_10;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=276 dst=r7 src=r0 offset=0 imm=1515847689
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847689);
    // EBPF_OP_STXW pc=277 dst=r10 src=r7 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=278 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=279 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=280 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=281 dst=r3 src=r0 offset=0 imm=4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=282 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=283 dst=r0 src=r0 offset=0 imm=11
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=284 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=285 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=286 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=287 dst=r1 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r1 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_10;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=288 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_10:
    // EBPF_OP_MOV64_IMM pc=289 dst=r1 src=r0 offset=0 imm=9
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=290 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=291 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=292 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=293 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=294 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=295 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=296 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=298 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=299 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[21].address);
    // EBPF_OP_MOV64_REG pc=300 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=301 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=302 dst=r1 src=r1 offset=0 imm=22
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[21].address);
    // EBPF_OP_CALL pc=304 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=305 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=307 dst=r0 src=r0 offset=15 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_11;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=308 dst=r7 src=r0 offset=0 imm=1515847690
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847690);
    // EBPF_OP_STXW pc=309 dst=r10 src=r7 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=310 dst=r4 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = r10;
    // EBPF_OP_ADD64_IMM pc=311 dst=r4 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=312 dst=r1 src=r6 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r6;
    // EBPF_OP_MOV64_REG pc=313 dst=r2 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r0;
    // EBPF_OP_LDDW pc=314 dst=r3 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = (uint64_t)4294967295;
    // EBPF_OP_MOV64_IMM pc=316 dst=r5 src=r0 offset=0 imm=4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r5 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=317 dst=r0 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=318 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=319 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=320 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=321 dst=r1 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r1 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_11;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=322 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_11:
    // EBPF_OP_MOV64_IMM pc=323 dst=r1 src=r0 offset=0 imm=10
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=324 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=325 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=326 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=327 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=328 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=329 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=330 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=332 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=333 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_IMM pc=334 dst=r0 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map_in_map_all_types.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=335 dst=r0 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map_in_map_all_types.c"
    return r0;
#line 243 "sample/undocked/map_in_map_all_types.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t hash_of_maps_all_types_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     16,
     "helper_id_16",
    },
    {
     {1, 40, 40}, // Version header.
     11,
     "helper_id_11",
    },
    {
     {1, 40, 40}, // Version header.
     32,
     "helper_id_32",
    },
};

static GUID hash_of_maps_all_types_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID hash_of_maps_all_types_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t hash_of_maps_all_types_maps[] = {
    23,
    25,
    27,
    29,
    31,
    33,
    35,
    37,
    39,
    41,
    43,
    44,
};

#pragma code_seg(push, "sample~1")
static uint64_t
hash_of_maps_all_types(void* context, const program_runtime_context_t* runtime_context)
#line 243 "sample/undocked/map_in_map_all_types.c"
{
#line 243 "sample/undocked/map_in_map_all_types.c"
    // Prologue.
#line 243 "sample/undocked/map_in_map_all_types.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r0 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r1 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r2 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r3 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r4 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r5 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r6 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r7 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r8 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r9 = 0;
#line 243 "sample/undocked/map_in_map_all_types.c"
    register uint64_t r10 = 0;

#line 243 "sample/undocked/map_in_map_all_types.c"
    r1 = (uintptr_t)context;
#line 243 "sample/undocked/map_in_map_all_types.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 243 "sample/undocked/map_in_map_all_types.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 243 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-8 imm=0
#line 245 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 245 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-8
#line 245 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r1 offset=0 imm=24
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[23].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=8 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=10 dst=r1 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=12 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_1;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=13 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=14 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=16 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=20 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_1;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=21 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
label_1:
    // EBPF_OP_MOV64_IMM pc=22 dst=r2 src=r0 offset=0 imm=11
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = IMMEDIATE(11);
    // EBPF_OP_STXW pc=23 dst=r10 src=r2 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-16));
    // EBPF_OP_STXW pc=24 dst=r10 src=r1 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=25 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=26 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=27 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r3 src=r0 offset=0 imm=-4
#line 151 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=29 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=31 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=32 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[25].address);
    // EBPF_OP_MOV64_REG pc=33 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=34 dst=r2 src=r0 offset=0 imm=-8
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=35 dst=r1 src=r1 offset=0 imm=26
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[25].address);
    // EBPF_OP_CALL pc=37 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=38 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_2;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=39 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=40 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=41 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=43 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=44 dst=r7 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=46 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_2;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=47 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r7, r0, OFFSET(0));
label_2:
    // EBPF_OP_MOV64_IMM pc=48 dst=r1 src=r0 offset=0 imm=12
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(12);
    // EBPF_OP_STXW pc=49 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=50 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=51 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=52 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=53 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=55 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=57 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=58 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[27].address);
    // EBPF_OP_MOV64_REG pc=59 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=60 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=61 dst=r1 src=r1 offset=0 imm=28
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[27].address);
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=64 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=68 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_3;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=69 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=70 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=71 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=72 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=73 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=76 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_3;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=77 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r1, r0, OFFSET(0));
label_3:
    // EBPF_OP_MOV64_IMM pc=78 dst=r2 src=r0 offset=0 imm=13
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = IMMEDIATE(13);
    // EBPF_OP_STXW pc=79 dst=r10 src=r2 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-16));
    // EBPF_OP_STXW pc=80 dst=r10 src=r1 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=81 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=82 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=83 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=84 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=85 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=87 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=88 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[29].address);
    // EBPF_OP_MOV64_REG pc=89 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=90 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=91 dst=r1 src=r1 offset=0 imm=30
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[29].address);
    // EBPF_OP_CALL pc=93 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=94 dst=r0 src=r0 offset=11 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_4;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDDW pc=95 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = (uint64_t)720575944674246688;
    // EBPF_OP_STXDW pc=97 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=98 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=99 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=100 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=102 dst=r7 src=r0 offset=0 imm=-2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967294;
    // EBPF_OP_JEQ_IMM pc=104 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_4;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_LDXW pc=105 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    READ_ONCE_32(r7, r0, OFFSET(0));
label_4:
    // EBPF_OP_MOV64_IMM pc=106 dst=r1 src=r0 offset=0 imm=14
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(14);
    // EBPF_OP_STXW pc=107 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=108 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=109 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=110 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=111 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=112 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=113 dst=r9 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=114 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=116 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=117 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[31].address);
    // EBPF_OP_MOV64_REG pc=118 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=119 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=120 dst=r1 src=r1 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[31].address);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=123 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=125 dst=r8 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=127 dst=r0 src=r0 offset=12 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_5;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=128 dst=r10 src=r9 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-16));
    // EBPF_OP_MOV64_IMM pc=129 dst=r8 src=r0 offset=0 imm=1515847695
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(1515847695);
    // EBPF_OP_STXW pc=130 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=131 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=132 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=133 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=134 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=135 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=136 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=137 dst=r0 src=r0 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=138 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_5;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=139 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = r0;
label_5:
    // EBPF_OP_MOV64_IMM pc=140 dst=r1 src=r0 offset=0 imm=15
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(15);
    // EBPF_OP_STXW pc=141 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=142 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=143 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=144 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=145 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=146 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=147 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=148 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=150 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=151 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[33].address);
    // EBPF_OP_MOV64_REG pc=152 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=153 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=154 dst=r1 src=r1 offset=0 imm=34
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[33].address);
    // EBPF_OP_CALL pc=156 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=157 dst=r0 src=r0 offset=12 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_6;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=158 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_IMM pc=159 dst=r7 src=r0 offset=0 imm=1515847696
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847696);
    // EBPF_OP_STXW pc=160 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=161 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=162 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=163 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=164 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=165 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=166 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=167 dst=r0 src=r0 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=168 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_6;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=169 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_6:
    // EBPF_OP_MOV64_IMM pc=170 dst=r1 src=r0 offset=0 imm=16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(16);
    // EBPF_OP_STXW pc=171 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=172 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=173 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=174 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=175 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=176 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=177 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=179 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=180 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[35].address);
    // EBPF_OP_MOV64_REG pc=181 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=182 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=183 dst=r1 src=r1 offset=0 imm=36
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[35].address);
    // EBPF_OP_CALL pc=185 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=186 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=188 dst=r8 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=190 dst=r0 src=r0 offset=12 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_7;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_STXW pc=191 dst=r10 src=r9 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r9, OFFSET(-16));
    // EBPF_OP_MOV64_IMM pc=192 dst=r8 src=r0 offset=0 imm=1515847697
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(1515847697);
    // EBPF_OP_STXW pc=193 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=194 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=195 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=196 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=197 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=198 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=199 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=200 dst=r0 src=r0 offset=0 imm=2
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=201 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_7;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=202 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = r0;
label_7:
    // EBPF_OP_MOV64_IMM pc=203 dst=r1 src=r0 offset=0 imm=17
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(17);
    // EBPF_OP_STXW pc=204 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=205 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=206 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=207 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=208 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=209 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=210 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=212 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=213 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[37].address);
    // EBPF_OP_MOV64_REG pc=214 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=215 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=216 dst=r1 src=r1 offset=0 imm=38
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[37].address);
    // EBPF_OP_CALL pc=218 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=219 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_8;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=220 dst=r7 src=r0 offset=0 imm=1515847698
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847698);
    // EBPF_OP_STXW pc=221 dst=r10 src=r7 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=222 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=223 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=224 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=225 dst=r3 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=226 dst=r0 src=r0 offset=0 imm=16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=227 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_8;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=228 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_8:
    // EBPF_OP_MOV64_IMM pc=229 dst=r1 src=r0 offset=0 imm=18
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(18);
    // EBPF_OP_STXW pc=230 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=231 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=232 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=233 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=234 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=235 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=236 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=238 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=239 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[39].address);
    // EBPF_OP_MOV64_REG pc=240 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=241 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=242 dst=r1 src=r1 offset=0 imm=40
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[39].address);
    // EBPF_OP_CALL pc=244 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=245 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDDW pc=247 dst=r8 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=249 dst=r0 src=r0 offset=9 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_9;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=250 dst=r8 src=r0 offset=0 imm=1515847699
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = IMMEDIATE(1515847699);
    // EBPF_OP_STXW pc=251 dst=r10 src=r8 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=254 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=255 dst=r3 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=256 dst=r0 src=r0 offset=0 imm=16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=257 dst=r0 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_9;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=258 dst=r8 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r8 = r0;
label_9:
    // EBPF_OP_MOV64_IMM pc=259 dst=r1 src=r0 offset=0 imm=19
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(19);
    // EBPF_OP_STXW pc=260 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=261 dst=r10 src=r8 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=262 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=263 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=264 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=265 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=266 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=268 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=269 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[41].address);
    // EBPF_OP_MOV64_REG pc=270 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=271 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=272 dst=r1 src=r1 offset=0 imm=42
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[41].address);
    // EBPF_OP_CALL pc=274 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=275 dst=r0 src=r0 offset=13 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_10;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=276 dst=r7 src=r0 offset=0 imm=1515847700
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847700);
    // EBPF_OP_STXW pc=277 dst=r10 src=r7 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=278 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=279 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=280 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=281 dst=r3 src=r0 offset=0 imm=4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=282 dst=r4 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=283 dst=r0 src=r0 offset=0 imm=11
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=284 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=285 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=286 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=287 dst=r1 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r1 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_10;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=288 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_10:
    // EBPF_OP_MOV64_IMM pc=289 dst=r1 src=r0 offset=0 imm=20
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(20);
    // EBPF_OP_STXW pc=290 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=291 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=292 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=293 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=294 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=295 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=296 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=298 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=299 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 151 "sample/undocked/map_in_map_all_types.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[43].address);
    // EBPF_OP_MOV64_REG pc=300 dst=r2 src=r10 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=301 dst=r2 src=r0 offset=0 imm=-8
#line 151 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=302 dst=r1 src=r1 offset=0 imm=44
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[43].address);
    // EBPF_OP_CALL pc=304 dst=r0 src=r0 offset=0 imm=1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LDDW pc=305 dst=r7 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=307 dst=r0 src=r0 offset=15 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r0 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_11;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_IMM pc=308 dst=r7 src=r0 offset=0 imm=1515847701
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = IMMEDIATE(1515847701);
    // EBPF_OP_STXW pc=309 dst=r10 src=r7 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=310 dst=r4 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 = r10;
    // EBPF_OP_ADD64_IMM pc=311 dst=r4 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r4 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=312 dst=r1 src=r6 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r6;
    // EBPF_OP_MOV64_REG pc=313 dst=r2 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r0;
    // EBPF_OP_LDDW pc=314 dst=r3 src=r0 offset=0 imm=-1
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = (uint64_t)4294967295;
    // EBPF_OP_MOV64_IMM pc=316 dst=r5 src=r0 offset=0 imm=4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r5 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=317 dst=r0 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_REG pc=318 dst=r1 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=319 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=320 dst=r1 src=r0 offset=0 imm=32
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=321 dst=r1 src=r0 offset=1 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    if (r1 == IMMEDIATE(0)) {
#line 247 "sample/undocked/map_in_map_all_types.c"
        goto label_11;
#line 247 "sample/undocked/map_in_map_all_types.c"
    }
    // EBPF_OP_MOV64_REG pc=322 dst=r7 src=r0 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r7 = r0;
label_11:
    // EBPF_OP_MOV64_IMM pc=323 dst=r1 src=r0 offset=0 imm=21
#line 247 "sample/undocked/map_in_map_all_types.c"
    r1 = IMMEDIATE(21);
    // EBPF_OP_STXW pc=324 dst=r10 src=r1 offset=-16 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-16));
    // EBPF_OP_STXW pc=325 dst=r10 src=r7 offset=-4 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=326 dst=r2 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=327 dst=r2 src=r0 offset=0 imm=-16
#line 247 "sample/undocked/map_in_map_all_types.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=328 dst=r3 src=r10 offset=0 imm=0
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=329 dst=r3 src=r0 offset=0 imm=-4
#line 247 "sample/undocked/map_in_map_all_types.c"
    r3 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=330 dst=r1 src=r1 offset=0 imm=45
#line 151 "sample/undocked/map_in_map_all_types.c"
    r1 = POINTER(runtime_context->map_data[44].address);
    // EBPF_OP_MOV64_IMM pc=332 dst=r4 src=r0 offset=0 imm=0
#line 151 "sample/undocked/map_in_map_all_types.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=333 dst=r0 src=r0 offset=0 imm=2
#line 151 "sample/undocked/map_in_map_all_types.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_MOV64_IMM pc=334 dst=r0 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map_in_map_all_types.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=335 dst=r0 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map_in_map_all_types.c"
    return r0;
#line 243 "sample/undocked/map_in_map_all_types.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        array_of_maps_all_types,
        "sample~2",
        "sample_ext",
        "array_of_maps_all_types",
        array_of_maps_all_types_maps,
        12,
        array_of_maps_all_types_helpers,
        5,
        336,
        &array_of_maps_all_types_program_type_guid,
        &array_of_maps_all_types_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        hash_of_maps_all_types,
        "sample~1",
        "sample_ext",
        "hash_of_maps_all_types",
        hash_of_maps_all_types_maps,
        12,
        hash_of_maps_all_types_helpers,
        5,
        336,
        &hash_of_maps_all_types_program_type_guid,
        &hash_of_maps_all_types_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 2;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 6;
    version->revision = 0;
}

#pragma data_seg(push, "map_initial_values")
// clang-format off
static const char* _outer_array_aom_initial_string_table[] = {
    "inner_array_aom",
};
// clang-format on

// clang-format off
static const char* _outer_array_hom_initial_string_table[] = {
    "inner_array_hom",
};
// clang-format on

// clang-format off
static const char* _outer_hash_aom_initial_string_table[] = {
    "inner_hash_aom",
};
// clang-format on

// clang-format off
static const char* _outer_hash_hom_initial_string_table[] = {
    "inner_hash_hom",
};
// clang-format on

// clang-format off
static const char* _outer_lpm_trie_aom_initial_string_table[] = {
    "inner_lpm_trie_aom",
};
// clang-format on

// clang-format off
static const char* _outer_lpm_trie_hom_initial_string_table[] = {
    "inner_lpm_trie_hom",
};
// clang-format on

// clang-format off
static const char* _outer_lru_hash_aom_initial_string_table[] = {
    "inner_lru_hash_aom",
};
// clang-format on

// clang-format off
static const char* _outer_lru_hash_hom_initial_string_table[] = {
    "inner_lru_hash_hom",
};
// clang-format on

// clang-format off
static const char* _outer_lru_percpu_aom_initial_string_table[] = {
    "inner_lru_percpu_aom",
};
// clang-format on

// clang-format off
static const char* _outer_lru_percpu_hom_initial_string_table[] = {
    "inner_lru_percpu_hom",
};
// clang-format on

// clang-format off
static const char* _outer_percpu_array_aom_initial_string_table[] = {
    "inner_percpu_array_aom",
};
// clang-format on

// clang-format off
static const char* _outer_percpu_array_hom_initial_string_table[] = {
    "inner_percpu_array_hom",
};
// clang-format on

// clang-format off
static const char* _outer_percpu_hash_aom_initial_string_table[] = {
    "inner_percpu_hash_aom",
};
// clang-format on

// clang-format off
static const char* _outer_percpu_hash_hom_initial_string_table[] = {
    "inner_percpu_hash_hom",
};
// clang-format on

// clang-format off
static const char* _outer_perf_aom_initial_string_table[] = {
    "inner_perf_aom",
};
// clang-format on

// clang-format off
static const char* _outer_perf_hom_initial_string_table[] = {
    "inner_perf_hom",
};
// clang-format on

// clang-format off
static const char* _outer_queue_aom_initial_string_table[] = {
    "inner_queue_aom",
};
// clang-format on

// clang-format off
static const char* _outer_queue_hom_initial_string_table[] = {
    "inner_queue_hom",
};
// clang-format on

// clang-format off
static const char* _outer_ringbuf_aom_initial_string_table[] = {
    "inner_ringbuf_aom",
};
// clang-format on

// clang-format off
static const char* _outer_ringbuf_hom_initial_string_table[] = {
    "inner_ringbuf_hom",
};
// clang-format on

// clang-format off
static const char* _outer_stack_aom_initial_string_table[] = {
    "inner_stack_aom",
};
// clang-format on

// clang-format off
static const char* _outer_stack_hom_initial_string_table[] = {
    "inner_stack_hom",
};
// clang-format on

static map_initial_values_t _map_initial_values_array[] = {
    {
        .header = {1, 48, 48},
        .name = "outer_array_aom",
        .count = 1,
        .values = _outer_array_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_array_hom",
        .count = 1,
        .values = _outer_array_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_hash_aom",
        .count = 1,
        .values = _outer_hash_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_hash_hom",
        .count = 1,
        .values = _outer_hash_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_lpm_trie_aom",
        .count = 1,
        .values = _outer_lpm_trie_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_lpm_trie_hom",
        .count = 1,
        .values = _outer_lpm_trie_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_lru_hash_aom",
        .count = 1,
        .values = _outer_lru_hash_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_lru_hash_hom",
        .count = 1,
        .values = _outer_lru_hash_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_lru_percpu_aom",
        .count = 1,
        .values = _outer_lru_percpu_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_lru_percpu_hom",
        .count = 1,
        .values = _outer_lru_percpu_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_percpu_array_aom",
        .count = 1,
        .values = _outer_percpu_array_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_percpu_array_hom",
        .count = 1,
        .values = _outer_percpu_array_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_percpu_hash_aom",
        .count = 1,
        .values = _outer_percpu_hash_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_percpu_hash_hom",
        .count = 1,
        .values = _outer_percpu_hash_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_perf_aom",
        .count = 1,
        .values = _outer_perf_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_perf_hom",
        .count = 1,
        .values = _outer_perf_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_queue_aom",
        .count = 1,
        .values = _outer_queue_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_queue_hom",
        .count = 1,
        .values = _outer_queue_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_ringbuf_aom",
        .count = 1,
        .values = _outer_ringbuf_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_ringbuf_hom",
        .count = 1,
        .values = _outer_ringbuf_hom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_stack_aom",
        .count = 1,
        .values = _outer_stack_aom_initial_string_table,
    },
    {
        .header = {1, 48, 48},
        .name = "outer_stack_hom",
        .count = 1,
        .values = _outer_stack_hom_initial_string_table,
    },
};
#pragma data_seg(pop)

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = _map_initial_values_array;
    *count = 22;
}

metadata_table_t map_in_map_all_types_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
