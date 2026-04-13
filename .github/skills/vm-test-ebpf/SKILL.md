---
name: vm-test-ebpf
description: >
  Deploy eBPF for Windows builds to a Hyper-V VM and run kernel tests.
  Use when asked to test changes on a VM, deploy a build, install eBPF,
  run kernel tests, or validate a fix end-to-end on real hardware.
---

# VM Test — Deploy & Run eBPF Kernel Tests

You are an automation agent. Your job is to deploy eBPF for Windows builds to a test VM and run kernel tests using the **hyperv-mcp** MCP tools. You execute these operations directly.

## Prerequisites

- The eBPF for Windows solution must already be built (use the `msbuild` skill if needed).
- A Hyper-V test VM must exist with test signing enabled and secure boot off.
- VM credentials must be stored in Credential Manager as target `TEST_VM`.

## Conventions

For MCP timeout conventions, output formats, file transfer patterns, service management,
hot-replace, and recovery escalation, see the **hyperv-deploy** skill
(`C:\git\mcp-tools\.github\skills\hyperv-deploy\SKILL.md`).

Project-specific conventions:

- Build output: `C:\git\ebpf-for-windows\x64\{Debug,Release}` (or `C:\git\ebpf-for-windows-<branch>\x64`). Ask the user for the build path if not specified.
- On the VM: builds deployed to `C:\` and extracted as `C:\Debug\` or `C:\Release\`
- MSI installs to `C:\ebpf`
- eBPF services: `eBPFSvc` (user-mode), `eBPFCore` (core driver), `NetEbpfExt` (network extension driver)
- MSI-installed driver paths: `C:\ebpf\drivers\EbpfCore.sys`, `C:\ebpf\drivers\NetEbpfExt.sys`
- Catch2 test filtering: see **Catch2 Arguments** under Test Executables Reference
- All test executables support `--list-tags` to list tags and `-l` to list test names

---

## Core Workflow

### Step 1: Connect to VM

See **hyperv-deploy** skill for VM setup patterns (find, restore, start, connect, retry).

```
list_vms(name_filter="ebpf")
connect_vm(vm_name="<name>", credential_target="TEST_VM")  → session_id
```

For a clean state: `restore_vm(vm_name="<name>", checkpoint_name="<name>", wait_for_ready=true)` before connecting.

### Step 2: Deploy Build

Copy only the files needed for testing (~55 MB, ~15s transfer). This uses globs to skip build intermediates (`.lib`, `.pdb`, `.obj`, `.spd` — 900+ MB). Mirrors the project's `deploy-ebpf.ps1.in --test` approach.
```
copy_to_vm(session_id="<id>",
           source=["<build>\\*.exe", "<build>\\*.dll", "<build>\\*.sys",
                   "<build>\\*.o", "<build>\\*.msi", "<build>\\*.cer",
                   "<build>\\*.ps1", "<build>\\*.psm1", "<build>\\*.guid",
                   "<build>\\*.wprp", "<build>\\expected", "<build>\\bad"],
           destination="C:\\Release")

# If status="running", poll:
get_command_status(command_id="<id>", timeout=45, include_output=false)
```

Where `<build>` is the build output path (e.g., `C:\\git\\ebpf-for-windows\\x64\\Release`).

If running CI/CD tests via `execute_ebpf_cicd_tests.ps1`, also copy `test_execution.json` from the repo's `scripts` directory:
```
copy_to_vm(session_id="<id>",
           source="<repo>\\scripts\\test_execution.json",
           destination="C:\\Release")
```

For **debugging** (need PDBs for crash analysis), deploy the full directory instead (~1 GB, ~3 min):
```
copy_to_vm(session_id="<id>",
           source="<build>",
           destination="C:\\")
```

### Step 3: Install eBPF

Install the MSI with all components:
```
invoke_command(session_id="<id>",
    command="msiexec.exe /i C:\\Release\\ebpf-for-windows.msi INSTALLFOLDER=C:\\ebpf ADDLOCAL=ALL /qn /norestart /l*v C:\\msi-install.log",
    initial_wait=30)
```

Wait a few seconds then verify services are running:
```
invoke_command(session_id="<id>", command="Start-Sleep 5")
get_services(session_id="<id>", names=["eBPFSvc", "NetEbpfExt", "eBPFCore"])
```

Expected: all three services show `Running` (Status=4). **Do not trust the msiexec exit code**— it may report 0 even on failure. Always verify by checking services. If services are missing, check the MSI log:
```
invoke_command(session_id="<id>",
    command="Get-Content C:\\msi-install.log -Tail 50",
    output_format="text")
```

#### Register program types (required)

After MSI install, run both export_program_info executables to register eBPF program types in the Windows registry. **Tests will fail with -22 (EINVAL) without this step.** The store persists across reboots — only re-run after a new build deployment or MSI reinstall. Safe to re-run anytime (idempotent).
```
invoke_command(session_id="<id>",
    command=".\\export_program_info.exe --clear; .\\export_program_info.exe; .\\export_program_info_sample.exe",
    working_directory="C:\\Release", initial_wait=30)
```

#### Install sample extension driver

The sample extension driver (`SampleEbpfExt`) is **not included in the MSI**. Install it as part of the standard setup — it is required for any test using `BPF_PROG_TYPE_SAMPLE`. Tests needing it fail with -22 (EINVAL) at program load.
```
invoke_command(session_id="<id>",
    command='sc.exe create SampleEbpfExt type=kernel start=auto binpath="C:\\Release\\sample_ebpf_ext.sys"; sc.exe start SampleEbpfExt',
    initial_wait=15)
```

### Step 4: Run Tests

**IMPORTANT:** Test executables share kernel eBPF resources and MUST run sequentially. Do NOT run multiple test executables in parallel — they will fail silently with exit_code=1. To run multiple tag groups efficiently, use Catch2 comma-separated tag syntax in a single invocation.

**Leaked programs cause cross-test failures.** If a test fails with error 23 (`EBPF_EXTENSION_FAILED_TO_LOAD`) on an attach call, or with unexpected errors that don't reproduce when run in isolation, suspect leaked programs from a prior test run. Check with `netsh ebpf show programs` and delete any leaked programs with `netsh ebpf delete program <ID>` before re-running. See **Investigating program leaks** under Debugging & Recovery for more.

#### Discover available tests
Use `--list-tags` or `-l` to find specific tests. The reference table below has common Quick tags.
```
invoke_command(session_id="<id>",
    command=".\\api_test.exe --list-tags",
    working_directory="C:\\Release",
    initial_wait=15)
```

#### Quick targeted tests (always set timeout)
Use a tag, test name, or comma-separated tags. Pick small tags for quick validation (e.g., `[divide_by_zero]`, `[helpers]`).
```
invoke_command(session_id="<id>",
    command=".\\api_test.exe -d 1 '[divide_by_zero],[helpers],[map_in_map],[pinned_map_enum]'",
    working_directory="C:\\Release",
    initial_wait=30,
    timeout=120)
```

#### Full test suite (long-running)
```
invoke_command(session_id="<id>",
    command=".\\api_test.exe -d 1",
    working_directory="C:\\Release",
    initial_wait=30,
    timeout=600)
```

For long-running tests (>2 min), use `retention="tail"` to save memory:
```
invoke_command(session_id="<id>",
    command=".\\socket_tests.exe -d 1 '[sock_addr_tests]'",
    working_directory="C:\\Release",
    initial_wait=30,
    timeout=900,
    retention="tail")
```

For polling, output searching, and viewing context around failures, see **hyperv-deploy** skill.

### Running CI/CD Tests

To run the same test suite as CI/CD on the VM, use `execute_ebpf_cicd_tests.ps1 -ExecuteOnHost`. This runs the tests directly on the VM rather than from a remote host.

#### Prerequisites

1. **PsExec64**: Required for system-level tests. Install via `Get-PSExec` from `common.psm1`:
```
invoke_command(session_id="<id>",
    command="powershell.exe -ExecutionPolicy Bypass -Command \"Import-Module C:\\Release\\common.psm1 -Force -ArgumentList 'TestLog.log'; Set-Location C:\\Release; Get-PSExec\"",
    working_directory="C:\\Release", initial_wait=30)
```
This downloads PSTools.zip from `https://download.sysinternals.com/files/PSTools.zip` and extracts `PsExec64.exe`.

2. **SysInternals EULA**: Accept via registry (PsExec blocks on EULA prompt otherwise):
```
invoke_command(session_id="<id>",
    command="powershell.exe -ExecutionPolicy Bypass -Command \"New-Item -Path 'HKCU:\\Software\\Sysinternals' -Force; Set-ItemProperty -Path 'HKCU:\\Software\\Sysinternals' -Name 'EulaAccepted' -Value 1\"",
    initial_wait=10)
```

3. **test_execution.json**: Must be in the same directory as the script (see Step 2 deploy note).

#### Running the tests

```
invoke_command(session_id="<id>",
    command="powershell.exe -ExecutionPolicy Bypass -File C:\\Release\\execute_ebpf_cicd_tests.ps1 -ExecuteOnHost -WorkingDirectory C:\\Release -TestMode 'CI/CD'",
    working_directory="C:\\Release",
    initial_wait=30, timeout=3600)
```

**Test modes:**
- `CI/CD` (default): api_test, bpftool_tests, sample_ext_app, socket_tests, then api_test again as SYSTEM via PsExec.
- `Regression`: Same as CI/CD but skips the SYSTEM-level api_test.
- `Stress`: Runs stress tests. Options: `MultiThread`, `RestartExtension`, `RestartEbpfCore`.
- `Performance`: Runs performance benchmarks. Release builds only.

**Notes:**
- The script's cleanup step may stop eBPF services. Expect to reconnect after completion.
- `test_execution.json` configures VM mapping and network interfaces only — it does NOT control which tests run. Tests are hardcoded in `run_driver_tests.psm1`.
- The script wraps each test with WPR tracing and saves ETL files to `C:\Release\TestLogs\`.

### Step 5: Collect Results (on failure)

Copy crash dumps and logs from the VM:
```
copy_from_vm(session_id="<id>",
    source=["C:\\Windows\\MEMORY.dmp", "C:\\Windows\\Minidump\\*.dmp"],
    destination=".\\TestLogs\\KernelDumps")

copy_from_vm(session_id="<id>",
    source=["C:\\Dumps\\*.dmp"],
    destination=".\\TestLogs\\UserDumps")
```

### Step 6: Clean Up Before Next Run

If you plan to run more tests, check for leaked programs that could interfere:
```
invoke_command(session_id="<id>",
    command="netsh ebpf show programs", initial_wait=15)
```
If programs remain, delete them before running the next test:
```
invoke_command(session_id="<id>",
    command="netsh ebpf delete program <ID>", initial_wait=15)
```

---

## Test Executables Reference

### Kernel Tests (require MSI installed on VM)

| Executable | Purpose | Quick tags | Timeout | Notes |
|-----------|---------|-----------|---------|-------|
| `api_test.exe` | eBPF API tests | `[divide_by_zero]`, `[helpers]`, `[native_tests]` | 600s | |
| `socket_tests.exe` | Socket/bind hook tests | `[bind_tests]`, `[sock_ops_tests]` | 1800s | `[sock_addr_tests]` ~10min |
| `sample_ext_app.exe` | Sample extension tests | `[sample_ext_test]` | 300s | Needs SampleEbpfExt driver |
| `bpftool_tests.exe` | bpftool CLI tests | — | 300s | Spawns `netsh` — if "not recognized", System32 is missing from PATH |
| `connect_redirect_tests.exe` | Connection redirect | — | 1800s | |
| `ebpf_stress_tests_km.exe` | Kernel stress tests | — | 1800s | `-tt=8 -td=5` (`-td` is per-test-case minutes; 8 tests × 5 min = 40 min total) |

### User-Mode Tests (can run on host OR VM)

These use user-mode mocks and don't require the MSI. They can run on the host directly, but also work on a VM with the build deployed:

| Executable | Purpose | Quick tags |
|-----------|---------|-----------|
| `unit_tests.exe` | Core eBPF + libbpf unit tests | `[sections]`, `[verification]`, `[hash_table]`, `[wer_report]` |
| `netebpfext_unit.exe` | Network extension unit tests | `[flow_classify]` |
| `bpf2c_tests.exe` | BPF-to-C compiler tests | `[bpf2c_raw]` |
| `ebpf_stress_tests_um.exe` | User-mode stress tests | — |

### Catch2 Arguments

- `-l` — list all test names
- `-d 1` — verbose duration reporting
- `'[tag]'` — run tests matching a tag (e.g., `'[ring_buffer]'`)
- `'[tag1],[tag2],[tag3]'` — run multiple tag groups in one invocation
- `'test name'` — run a specific test by name
- `~'pattern'` — exclude tests matching pattern

---

## Component Hot-Replace Reference

For the generic stop→copy→start pattern and iterative fix-and-test cycle, see **hyperv-deploy** skill. Below is the eBPF-specific component mapping:

| Component | Service to stop | Install path | Notes |
|---|---|---|---|
| Test executables | — | `C:\Release\` | Just copy, no restart |
| `ebpfapi.dll` | — | `C:\ebpf\` | Tests load fresh. Restart eBPFSvc only if service behavior changed. |
| `ebpfsvc.exe` | — | Copy → restart eBPFSvc | |
| `.sys` BPF programs | — (unload first) | `C:\Release\` | `netsh ebpf delete program <ID>` → copy |
| `NetEbpfExt.sys` / `SampleEbpfExt.sys` | NetEbpfExt / SampleEbpfExt | `C:\ebpf\drivers\` | Unload programs on hook first (see below) |
| `EbpfCore.sys` | eBPFSvc → eBPFCore | `C:\ebpf\drivers\` | Re-run `export_program_info` after |

### Service stop dependencies

- **eBPFCore** requires stopping **eBPFSvc** first (holds handles → STOP_PENDING).
- **Extension drivers** (NetEbpfExt, SampleEbpfExt) stop independently.

### Stale programs after extension restart

If an extension driver is stopped while programs using its hooks are still loaded, those programs become **stale** — they remain listed in `netsh ebpf show programs` but new program loads on that hook **fail**. Fix: unload programs on that hook **before** stopping the extension driver.

Hook-to-driver mapping:
- **NetEbpfExt**: `sock_addr` (connect, recv_accept), `bind`, `sock_ops`, `xdp` hooks
- **SampleEbpfExt**: `sample` hooks
- **eBPFCore**: owns all programs — stopping eBPFCore cleans up everything

### Full stack replacement (stop order)

```
# Stop (reverse dependency order):
manage_service — eBPFSvc → SampleEbpfExt → NetEbpfExt → eBPFCore
# Copy all components to C:\ebpf\drivers\ and C:\ebpf\
# Start (forward order):
manage_service — eBPFCore → NetEbpfExt → SampleEbpfExt → eBPFSvc
# Re-register: export_program_info.exe --clear; export_program_info.exe; export_program_info_sample.exe
```

---

## Common Scenarios

### Run tests with ETW tracing

```
invoke_command(session_id="<id>",
    command="pktmon start -m real-time --trace -p '{394f321c-5cf4-404c-aa34-4df1428a7f9c}' -l 5 -k 0xFFFFFFFF -p '{f2f2ca01-ad02-4a07-9e90-95a2334f3692}' -l 5 -k 0xFFFFFFFF",
    initial_wait=10)

# ... run tests ...

invoke_command(session_id="<id>", command="pktmon stop")
```

ETW provider GUIDs:
- eBPF Core: `{394f321c-5cf4-404c-aa34-4df1428a7f9c}`
- NetEbpfExt: `{f2f2ca01-ad02-4a07-9e90-95a2334f3692}`

---

## Debugging & Recovery

For the general recovery escalation (cancel → kill → reboot → restore), see **hyperv-deploy** skill.

### Service stuck in STOP_PENDING
eBPFCore gets stuck when eBPFSvc holds handles. Stop eBPFSvc first, or kill it:
```
manage_service(session_id="<id>", name="eBPFSvc", action="stop")
manage_service(session_id="<id>", name="eBPFCore", action="stop")
```
Fallback: `kill_process(session_id="<id>", name="ebpfsvc")`

### Tests fail with -22 (EINVAL)

Check two things: the program type store AND driver status.

**1. Check drivers are loaded:**
```
invoke_command(session_id="<id>",
    command="sc.exe query eBPFCore | Select-String STATE; sc.exe query NetEbpfExt | Select-String STATE; sc.exe query SampleEbpfExt | Select-String STATE",
    initial_wait=15)
```
All three should show `RUNNING`. If SampleEbpfExt is missing and only SAMPLE-type tests fail (e.g., `[perf_buffer]` subset), that's the cause — install it per Step 3.

**2. Check the program type store:**
```
invoke_command(session_id="<id>",
    command="$sd = @(Get-ChildItem 'HKLM:\\SOFTWARE\\eBPF\\Providers\\SectionData' -EA SilentlyContinue | % { $_.PSChildName }); $td = @(Get-ChildItem 'HKLM:\\SOFTWARE\\eBPF\\Providers\\ProgramData' -EA SilentlyContinue | % { $t = Get-ItemProperty \"$($_.PSPath)\\TypeDescriptor\" -EA SilentlyContinue; if ($t) { $t.Name } }); $gh = @(Get-ChildItem 'HKLM:\\SOFTWARE\\eBPF\\Providers\\GlobalHelpers' -EA SilentlyContinue); echo \"eBPF store: $($td.Count) types, $($sd.Count) sections, $($gh.Count) helpers\"; if ($td.Count -gt 0) { echo \"Types: $($td -join ', ')\" }; if ($sd.Count -gt 0) { echo \"Sections: $($sd -join ', ')\" }",
    initial_wait=15)
```
Healthy output: `4 types, 7 sections, 34 helpers` with types `sockops, bind, sock_addr, sample`.

Fix: re-run the export executables (no driver restart needed — takes effect immediately):
```
invoke_command(session_id="<id>",
    command=".\\export_program_info.exe --clear; .\\export_program_info.exe; .\\export_program_info_sample.exe",
    working_directory="C:\\Release", initial_wait=30)
```

### Investigating program leaks
When debugging suspected leaked eBPF programs, chain `netsh ebpf show programs` after the test command:
```
invoke_command(session_id="<id>",
    command=".\\api_test.exe -d 1 '[helpers]' 2>&1; echo '---EXIT:' $LASTEXITCODE '---'; netsh ebpf show programs",
    working_directory="C:\\Release",
    initial_wait=30, timeout=120)
```
The programs table should be empty after clean test runs.

### Analyzing large test output
```
search_command_output(command_id="<id>", pattern="FAILED|assert", max_results=20)
get_command_output(command_id="<id>", around_line=<N>, max_lines=50)
```

### Check MSI install log on failure
```
invoke_command(session_id="<id>",
    command="Get-Content C:\\msi-install.log | Select-Object -Last 50",
    output_format="text")
```

---

## Important Notes

- **Submodule updates**: After updating any git submodule, run `.\scripts\initialize_ebpf_repo.ps1` before building. This regenerates CMake projects and restores NuGet packages.
- **BPF programs**: Test executables expect `.sys` files in the same directory. Deploy the full build directory.
- **Test isolation**: Test executables share kernel eBPF resources and MUST run sequentially. Do NOT run multiple test executables in parallel.
- **Leaked programs cause cross-test failures.** If a test fails with error 23 (`EBPF_EXTENSION_FAILED_TO_LOAD`), check with `netsh ebpf show programs` and delete leaked programs before re-running.

For general notes on elevation, test signing, debug CRT, PATH handling, execution policy,
parallel VMs, and output format, see the **hyperv-deploy** skill.
