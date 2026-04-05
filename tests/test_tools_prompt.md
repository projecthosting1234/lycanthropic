# MCP Tool Integration Test Suite

You are running an automated integration test of all MCP tools available in this pipeline.
There are 44 tests across 6 categories. Execute each test sequentially.
For each test, print the result in this exact format:

```
TEST <number>: <tool_name> — PASS
TEST <number>: <tool_name> — FAIL (reason: <brief reason>)
```

After each category, print:
```
CATEGORY <N> SUMMARY: X/Y passed
```

**STOP GATE:** If Category 1 scores <15/18, print `STOP GATE FAILED — aborting` and stop immediately. The remaining tests require a working debugger connection.

At the very end, print a final summary table.

## Test Files

- Valid exploit source: `{VALID_EXPLOIT_C}`
- Invalid exploit source: `{INVALID_EXPLOIT_C}`
- Iteration directory: `{ITERATION_DIR}`
- Driver name: `{DRIVER_NAME}`

---

## Category 1 — Essential / VM + Connection (18 tests, STOP GATE)

Tests basic connectivity and core debugger tools.

### TEST 1.01 — get_connection_status
Call `get_connection_status()`.
**Pass:** Response contains `is_connected: true` (or `"is_connected": true`) AND `is_broken_in: true` (or `"is_broken_in": true`).

### TEST 1.02 — validate_connection
Call `validate_connection()`.
**Pass:** Response shows vertarget test PASS and module_nt test PASS.

### TEST 1.03 — windbg_command("vertarget")
Call `windbg_command` with command `vertarget`.
**Pass:** Output contains "Windows" and a build number.

### TEST 1.04 — windbg_command("lm")
Call `windbg_command` with command `lm`.
**Pass:** Output contains "nt" and lists at least 5 modules.

### TEST 1.05 — get_registers
Call `get_registers()`.
**Pass:** Response contains `rax`, `rsp`, and `rip` with hexadecimal values.

### TEST 1.06 — get_callstack
Call `get_callstack()`.
**Pass:** At least one frame contains "nt!" in the symbol name.

### TEST 1.07 — get_irql
Call `get_irql()`.
**Pass:** Response mentions IRQL and includes a level value.

### TEST 1.08 — list_modules
Call `list_modules()`.
**Pass:** Returns a JSON array (or structured list) with entries containing name, start address, and size.

### TEST 1.09 — get_process_list
Call `get_process_list()`.
**Pass:** At least one entry has `"System"` as the image name.

### TEST 1.10 — resolve_symbol
Call `resolve_symbol` with symbol `nt!NtCreateFile`.
**Pass:** Returns a hexadecimal kernel address (starts with `0xfffff` or similar kernel range).

### TEST 1.11 — evaluate_expression
Call `evaluate_expression` with expression `poi(nt!PsInitialSystemProcess)`.
**Pass:** Returns a hexadecimal value starting with `ffff` (kernel pointer).

### TEST 1.12 — read_memory
First, resolve `nt` module base address (use `evaluate_expression("nt")` or `resolve_symbol("nt")`).
Then call `read_memory` with that address and size 16.
**Pass:** Output contains `4d 5a` (MZ header bytes) or `4D 5A`.

### TEST 1.13 — write_memory round-trip
1. Read 8 bytes from `@rsp-0x100` (save as original).
2. Write `4142434445464748` to `@rsp-0x100`.
3. Read 8 bytes from `@rsp-0x100` — verify it contains `41 42 43 44 45 46 47 48`.
4. Write back the original bytes to restore.
**Pass:** Read-back matches written bytes AND original is restored.

### TEST 1.14 — set_breakpoint + remove_breakpoint
1. Resolve `nt!NtCreateFile` address.
2. Call `set_breakpoint` at that address.
3. Call `remove_breakpoint` to remove it (use the breakpoint ID from step 2).
**Pass:** Breakpoint is created (returns an ID or index) and cleanly removed without error.

### TEST 1.15 — break_execution
Call `break_execution()` while already broken in.
**Pass:** Returns success or no-op indication (should not error when already broken in).

### TEST 1.16 — get_build_profile
Call `get_build_profile()`.
**Pass:** Returns JSON with `build_number` and `struct_offsets` fields.

### TEST 1.17 — fingerprint_target
Call `fingerprint_target()`.
**Pass:** Returns JSON with `build_number` and `_EPROCESS` offset information.

### TEST 1.18 — get_struct_offset
Call `get_struct_offset` with struct `nt!_EPROCESS` and field `Token`.
**Pass:** Returns a hex offset value (e.g. `0x248` or similar).

---

## Category 2 — Advanced WinDbg (7 tests)

### TEST 2.01 — get_idt
Call `get_idt()`.
**Pass:** Response contains IDT entries with kernel addresses.

### TEST 2.02 — get_ssdt
Call `get_ssdt()`.
**Pass:** Response contains service table entries (syscall table).

### TEST 2.03 — get_driver_dispatch
Call `get_driver_dispatch` with driver name `{DRIVER_NAME}`.
**Pass:** Response contains an IRP_MJ_DEVICE_CONTROL dispatch entry (or MajorFunction table).

### TEST 2.04 — get_object_info
Call `get_object_info` with object path `\\Device\\Nal`.
**Pass:** Object information is returned (type, name, or address).

### TEST 2.05 — get_token
Call `get_token` with target `current`.
**Pass:** Response contains token information with privileges and/or groups.

### TEST 2.06 — dump_struct
1. First get the System EPROCESS: `evaluate_expression("poi(nt!PsInitialSystemProcess)")`.
2. Call `dump_struct` with struct `nt!_EPROCESS` and the EPROCESS address.
**Pass:** Output contains fields like `UniqueProcessId` and `Token`.

### TEST 2.07 — search_memory
1. Resolve `nt` base address.
2. Call `search_memory` with start address = nt base, length `0x1000`, and pattern `4D5A` (MZ header bytes).
**Pass:** At least one match found at or near nt base.

---

## Category 3 — Valid Exploit Workflow (4 tests)

These tests use the known-working iqvw64e exploit (SSH-safe variant, no system("cmd.exe")).

### TEST 3.01 — compile_exploit (valid)
Call `compile_exploit` with source_path `{VALID_EXPLOIT_C}`.
**Pass:** Response shows `success: true` (or compilation succeeded) and an exe_path is returned.

### TEST 3.02 — run_exploit (valid)
Call `run_exploit` with the exe_path from test 3.01 and timeout 120.
**Pass:** stdout output contains `SUCCESS` — the exploit ran and escalated privileges. Note: no verification flag file exists on the debug VM, so `FLAG{` is not expected here — that's tested via `final_verification` in Category 6.

### TEST 3.03 — recover_vm
Call `recover_vm()`.
**Pass:** Response indicates recovery succeeded (status: recovered or similar) and the driver is still loaded (`driver_loaded: true` or equivalent). If the VM didn't crash, a graceful "already healthy" response also counts as PASS.

### TEST 3.04 — breakpoint + resume_and_wait
1. Set a breakpoint on `nt!NtCreateFile`.
2. Call `resume_and_wait` with timeout 30.
**Pass:** Returns either `breakpoint_hit` (meaning the BP triggered) or `timeout_break` (meaning it timed out and broke back in). Either result is acceptable — this test validates the resume/break cycle works.
3. Remove the breakpoint and break back in if needed.

---

## Category 4 — Invalid Exploit Workflow (3 tests)

These tests use the intentionally broken exploit (wrong IOCTL code).

### TEST 4.01 — compile_exploit (invalid)
Call `compile_exploit` with source_path `{INVALID_EXPLOIT_C}`.
**Pass:** Compilation succeeds (`success: true`) — the C code is syntactically valid, just logically wrong.

### TEST 4.02 — run_exploit (invalid)
Call `run_exploit` with the exe_path from test 4.01 and timeout 60.
**Pass:** stdout does NOT contain `SUCCESS`. Expected: `FAILURE` appears in stdout (the exploit fails at the KUSD read check because the wrong IOCTL code is rejected by the driver).

### TEST 4.03 — recover_vm + get_connection_status (after invalid)
1. Call `recover_vm()` to ensure the VM is healthy.
2. Call `get_connection_status()` to verify debugger connection.
**Pass:** VM recovered, `is_broken_in: true`.

---

## Category 5 — ROP / angrop_mcp (4 tests)

These tests verify the angrop MCP server for ROP chain building.
Note: First call may take several minutes for gadget analysis. Be patient.

### TEST 5.01 — rop_summary
Call `rop_summary` with binary `kernel`.
**Pass:** Response shows `total_gadgets > 0` (gadgets were found in ntoskrnl.exe).

### TEST 5.02 — rop_gadget_search
Call `rop_gadget_search` with gadget `pop rax; ret` and binary `kernel`.
**Pass:** At least one matching gadget is returned with an address.

### TEST 5.03 — rop_build_chain
Call `rop_build_chain` with goal `set_regs`, registers `{"rax": "0x41414141"}`, and binary `kernel`.
**Pass:** A non-empty ROP chain is returned (list of addresses/values).

### TEST 5.04 — rop_search_bytes
Call `rop_search_bytes` with hex_pattern `C3` and binary `kernel`.
**Pass:** At least one address is returned where the byte `0xC3` (ret instruction) was found.

---

## Category 6 — Workflow Integration (6 tests)

These tests verify multi-step workflows that mirror real pipeline usage.
They exercise the compile → run → recover cycle in realistic sequences.

### TEST 6.01 — Invalid then Valid (retry flow)
This tests the typical "exploit fails, fix it, retry" workflow:
1. Compile the invalid exploit (`{INVALID_EXPLOIT_C}`).
2. Run it with `run_exploit` (timeout 60). Confirm stdout contains `FAILURE` (not `SUCCESS`).
3. Now compile the valid exploit (`{VALID_EXPLOIT_C}`).
4. Run it with `run_exploit` (timeout 120). Confirm stdout contains `SUCCESS`.
**Pass:** The invalid run fails as expected, then the valid run succeeds — proving the pipeline can recover from a failed exploit and successfully run a corrected one in the same session.

### TEST 6.02 — Double run_exploit (valid twice)
Tests running the same exploit twice in a row without restarting the VM:
1. Compile the valid exploit (`{VALID_EXPLOIT_C}`) if not already compiled.
2. Run it with `run_exploit` (timeout 120). Confirm `SUCCESS`.
3. Call `recover_vm()` to restore debugger state.
4. Run the same exploit exe again with `run_exploit` (timeout 120). Confirm `SUCCESS`.
**Pass:** Both runs produce `SUCCESS` — the VM/debugger recovers cleanly between runs.

### TEST 6.03 — Compile error handling
Test compilation of a non-existent source file:
1. Call `compile_exploit` with source_path `{ITERATION_DIR}/nonexistent_file.c`.
**Pass:** Returns `success: false` with an error message about the file not being found. Does NOT crash or hang.

### TEST 6.04 — run_exploit timeout handling
Test that run_exploit handles a long-running/hanging process:
1. Compile the valid exploit.
2. Run it with `run_exploit` with a very short timeout (timeout 5).
**Pass:** Returns within a reasonable time (~10-15 seconds) with either a timeout status or the exploit output. Does NOT hang indefinitely.

### TEST 6.05 — Breakpoint persistence across resume cycles
Tests that breakpoints survive resume/break cycles:
1. Set a breakpoint on `nt!NtOpenFile`.
2. Call `resume_and_wait` with timeout 15.
3. After breaking back in, verify the breakpoint still exists (call `windbg_command("bl")` — the breakpoint list should show the BP).
4. Call `resume_and_wait` with timeout 15 again.
5. After breaking back in, call `windbg_command("bl")` again to verify BP still listed.
6. Remove the breakpoint.
**Pass:** The breakpoint appears in `bl` output after both resume cycles, and is cleanly removed at the end.

### TEST 6.06 — Full cycle: compile → run_exploit → recover → get_connection_status
End-to-end workflow matching a real iteration:
1. Call `get_connection_status()` — verify connected and broken in.
2. Compile the valid exploit (`{VALID_EXPLOIT_C}`).
3. Run it with `run_exploit` (timeout 120).
4. Call `recover_vm()`.
5. Call `get_connection_status()` — verify still connected and broken in.
6. Call `windbg_command("lm")` — verify modules still visible (debugger fully functional post-recovery).
**Pass:** All 6 steps succeed. The pipeline starts healthy, runs an exploit, and returns to a fully healthy state.

### TEST 6.07 — final_verification (valid exploit)
This tests the full clean-room verification pipeline. `final_verification` spins up a SEPARATE fresh VM (no debugger), plants a SYSTEM-only flag file, creates a non-admin user, runs the exploit as that user, and checks whether `FLAG{...}` appears in stdout.
1. Compile the valid exploit (`{VALID_EXPLOIT_C}`) if not already compiled from a previous test.
2. Call `final_verification` with the compiled exe_path, driver_path `dataset/{DRIVER_NAME}.sys`, and service_name `{DRIVER_NAME}`.
   NOTE: This takes 3-5 minutes (VM boot + setup + exploit execution + cleanup). Be patient.
**Pass:** Response JSON has `"passed": true` and `exploit_stdout` contains `FLAG{`.

### TEST 6.08 — final_verification (invalid exploit)
Same as 6.07 but with the broken exploit — verifies that `final_verification` correctly reports failure.
1. Compile the invalid exploit (`{INVALID_EXPLOIT_C}`) if not already compiled.
2. Call `final_verification` with the compiled exe_path, driver_path `dataset/{DRIVER_NAME}.sys`, and service_name `{DRIVER_NAME}`.
**Pass:** Response JSON has `"passed": false`. The exploit stdout should contain `FAILURE` (wrong IOCTL rejected) and NOT contain `FLAG{`.

---

## Final Summary

After all categories are complete (or after a STOP GATE failure), print:

```
============================================
FINAL TEST RESULTS
============================================
Category 1 (Essential):      XX/18
Category 2 (Advanced):       XX/7
Category 3 (Valid Exploit):   XX/4
Category 4 (Invalid Exploit): XX/3
Category 5 (ROP):            XX/4
Category 6 (Workflows):      XX/8
--------------------------------------------
TOTAL:                        XX/44
============================================
```

If all 44 pass, print: `ALL TESTS PASSED`
Otherwise, list the failed test numbers.
