// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "Verifier.h"
#include "api_common.hpp"
#include "ebpf_api.h"
#include "ebpf_shared_framework.h"
#include "ebpf_verifier_wrapper.hpp"
#include "platform.hpp"
#include "windows_platform_service.hpp"

#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>

static ebpf_result_t
_analyze(prevail::RawProgram& raw_prog, const char** error_message, uint32_t* error_message_size = nullptr)
{
    std::variant<prevail::InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<prevail::InstructionSeq>(prog_or_error)) {
        *error_message = allocate_string(std::get<std::string>(prog_or_error), error_message_size);
        return EBPF_VERIFICATION_FAILED; // Error;
    }
    prevail::InstructionSeq& prog = std::get<prevail::InstructionSeq>(prog_or_error);

    // First try optimized for the success case.
    prevail::ebpf_verifier_options_t options{};
    ebpf_api_verifier_stats_t stats;
    options.cfg_opts.check_for_termination = true;
    bool res = ebpf_verify_program(std::cout, prog, raw_prog.info, options, &stats);
    if (!res) {
        // On failure, retry to get the more detailed error message.
        std::ostringstream oss;
        options.verbosity_opts.simplify = false;
        options.verbosity_opts.print_failures = true;
        // Until https://github.com/vbpf/ebpf-verifier/issues/643 is fixed, don't set options.assume_assertions to true.
        (void)ebpf_verify_program(oss, prog, raw_prog.info, options, &stats);

        *error_message = allocate_string(oss.str(), error_message_size);
        return EBPF_VERIFICATION_FAILED; // Error;
    }
    return EBPF_SUCCESS; // Success.
}

_Must_inspect_result_ ebpf_result_t
verify_byte_code(
    const GUID* program_type,
    _In_reads_(instruction_count) const ebpf_inst* instruction_array,
    uint32_t instruction_count,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_ uint32_t* error_message_size)
{
    std::ostringstream error;
    const prevail::ebpf_platform_t* platform = &g_ebpf_platform_windows_service;
    std::vector<ebpf_inst> instructions{instruction_array, instruction_array + instruction_count};
    prevail::ProgramInfo info{platform};
    std::string section;
    std::string file;
    try {
        info.type = *get_program_type_windows(*program_type);
    } catch (std::runtime_error e) {
        error << "error: " << e.what();
        *error_message = allocate_string(error.str(), error_message_size);
        return EBPF_VERIFICATION_FAILED;
    }

    prevail::RawProgram raw_prog{file, section, 0, {}, instructions, info};

    return _analyze(raw_prog, error_message, error_message_size);
}
