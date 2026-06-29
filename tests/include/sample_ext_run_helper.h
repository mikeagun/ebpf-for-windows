// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "catch_wrapper.hpp"
#include "sample_ext_ioctls.h"

#include <vector>

// Helper that opens the sample eBPF extension device and invokes the program
// currently attached to the sample hook via IOCTL. This dispatches the program
// through the real sample-extension hook (the kernel-mode equivalent of the
// usersim single_instance_hook_t::fire path), mapping the supplied output
// buffer into the program context's data_start/data_end. Include this header
// after the platform headers that provide the Win32 file/IOCTL APIs.
struct _sample_extension_helper
{
  public:
    _sample_extension_helper() : device_handle(INVALID_HANDLE_VALUE)
    {
        // Open handle to test eBPF extension device.
        REQUIRE(
            (device_handle = ::CreateFileW(
                 SAMPLE_EBPF_EXT_DEVICE_WIN32_NAME,
                 GENERIC_READ | GENERIC_WRITE,
                 0,
                 nullptr,
                 CREATE_ALWAYS,
                 FILE_ATTRIBUTE_NORMAL,
                 nullptr)) != INVALID_HANDLE_VALUE);
    }

    ~_sample_extension_helper()
    {
        if (device_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(device_handle);
        }
    }

    void
    invoke(std::vector<char>& input_buffer, std::vector<char>& output_buffer)
    {
        uint32_t count_of_bytes_returned;

        // Issue IOCTL.
        REQUIRE(
            ::DeviceIoControl(
                device_handle,
                IOCTL_SAMPLE_EBPF_EXT_CTL_RUN,
                input_buffer.data(),
                static_cast<uint32_t>(input_buffer.size()),
                output_buffer.data(),
                static_cast<uint32_t>(output_buffer.size()),
                (unsigned long*)&count_of_bytes_returned,
                nullptr) == TRUE);
    }

    void
    invoke_batch(std::vector<char>& input_buffer, std::vector<char>& output_buffer)
    {
        uint32_t count_of_bytes_returned;

        // Issue IOCTL.
        REQUIRE(
            ::DeviceIoControl(
                device_handle,
                IOCTL_SAMPLE_EBPF_EXT_CTL_RUN_BATCH,
                input_buffer.data(),
                static_cast<uint32_t>(input_buffer.size()),
                output_buffer.data(),
                static_cast<uint32_t>(output_buffer.size()),
                (unsigned long*)&count_of_bytes_returned,
                nullptr) == TRUE);
    }

  private:
    HANDLE device_handle;
};
