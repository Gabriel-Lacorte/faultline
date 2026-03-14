# FAULTLINE

A user-mode EDR/AV killer that leverages a vulnerable driver (`AMDRyzenMaster`) to silently eliminates protected processes by corrupting their page table entries.

---

## How It Works

### PTE Corruption

Instead of terminating a process through standard APIs, the tool attacks at the hardware paging level.

Every process has a set of page tables that the CPU's MMU uses to translate virtual addresses to physical memory.
These tables form a 4-level hierarchy: a virtual address is split into indices for the `PML4` (bits 47-39), `PDPT` (bits 38-30), `PD` (bits 29-21), and `PT` (bits 20–12), with bits 11–0 as the page offset. The final level, `PTE` is the target.

Each PTE contains control bits that the CPU enforces on every memory access:

| Bit | Name | Purpose |
|-----|------|---------|
| 0 | Present | Page is mapped in physical memory |
| 1 | Writable | Page can be written to |
| 2 | User | Page is accessible from user-mode |
| 7 | Large Page | Entry maps a 2MB/1GB page |
| 63 | NX | Page cannot be executed |

The tool walks the target process's page tables using its CR3 register, locates the PTEs that map the `.text` section of the main image, and sets the NX bit (bit 63) on each PTE.
The next time any thread in the target process fetches an instruction from `.text`, the CPU raises a `#PF` (Page Fault) with an execution-disable violation. The Windows kernel delivers `STATUS_ACCESS_VIOLATION` to the process, which crashes with no way to catch or prevent it.

### EPROCESS Offset Resolution

All `EPROCESS` structure offsets are resolved at runtime, no hardcoded offsets, making the tool work across all Windows builds.

The tool loads `ntoskrnl.exe` into user-mode (without resolving imports), finds exported accessor functions, and disassembles them to extract the `[rcx+disp32]` displacement, which corresponds directly to the `EPROCESS` field offset.
For example, `PsGetProcessId` contains `mov rax, [rcx+0x2F8]`, revealing that `UniqueProcessId` lives at offset `0x2F8` on that build.

Resolved offsets:
| Field | Export Used |
|-------|-----------|
| `UniqueProcessId` | `PsGetProcessId` |
| `ActiveProcessLinks` | `UniqueProcessId + 8` (invariant) |
| `ImageFileName` | `PsGetProcessImageFileName` |
| `SectionBaseAddress` | `PsGetProcessSectionBaseAddress` |
| `Peb` | `PsGetProcessPeb` |

For `DirectoryTableBase`, which has no accessor export, a brute-force scan is used against the System process (`EPROCESS` at `PsInitialSystemProcess`): every QWORD at offsets `0x18`-`0x50` is tested as a potential CR3 by walking the page tables to ntoskrnl's base address and checking for the `MZ` magic bytes.

The `UserDirectoryTableBase` (for KVAS) is resolved similarly against a target process, testing all QWORD fields that can produce a valid user-space page walk.

### KVAS Awareness

On systems with Kernel Virtual Address Shadow enabled, each process has two CR3 values:
- Kernel CR3: maps both kernel and user address space
- User CR3: maps only user address space

The tool detects KVAS status and resolves both `DirectoryTableBase` and `UserDirectoryTableBase` offsets. For PTE corruption, the user CR3 is preferred since it contains the active user-space page mappings. If KVAS is not active, it falls back to the kernel CR3.

---

## Usage

1. Load `AMDRyzenMaster.sys` as a kernel service (the vulnerable driver must be running)
2. Run `killer.exe` as Administrator

```
> killer.exe
 + ntoskrnl    0xFFFFF80012345000
 + win32k      0xFFFFC00098765000
 + eprocess offsets: pid=0x2F8 links=0x300 img=0x5A8 sec=0x520 peb=0x550
 + dtb offset 0x28 verified (2mb page), cr3=0x1AD000
 * entering kill loop (2 targets)
 + found MsMpEng.exe (pid=4832 eproc=0xFFFF... kcr3=0x... ucr3=0x... base=0x7FF...)
 * corrupting pte's for MsMpEng.exe (pid=4832 cr3=0x...)
 + corrupted 16 pte's for MsMpEng.exe (pid=4832)
```

The tool runs in a continuous loop, detecting and killing target processes every second for respawned instances.

---

## Disclaimer

This project is provided for educational and authorized security research purposes only. It demonstrates techniques used in real-world offensive security tooling to help defenders understand and build detections against BYOVD-based attacks.

Do not use this tool against systems you do not own or have explicit authorization to test. The author is not responsible for any misuse.
