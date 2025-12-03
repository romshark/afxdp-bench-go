# afxdp-bench-go

An [AF_XDP](https://docs.kernel.org/networking/af_xdp.html) benchmark in pure Go.

## Prerequisites (Ubuntu)

```sh
sudo apt update
sudo apt install -y \
  build-essential \
  clang \
  llvm \
  libelf-dev \
  linux-headers-$(uname -r) \
  pkg-config \
  libbpf-dev
```

Also install [Go 1.25.4](https://go.dev/).

## Results on BlueField-2

The following results were achieved on
[NVIDIA BlueField-2 DPUs](https://www.nvidia.com/content/dam/en-zz/Solutions/Data-Center/documents/datasheet-nvidia-bluefield-2-dpu.pdf).

<details>

<summary><strong>CPU: Intel(R) Xeon(R) w5-2455X</strong></summary>

```sh
$ uname -a && lscpu && numactl --hardware && cat /proc/cmdline && cpupower frequency-info | sed -n '1,20p'

Linux <redacted> 6.8.0-87-generic #88~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Oct 14 14:03:14 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          46 bits physical, 57 bits virtual
  Byte Order:             Little Endian
CPU(s):                   24
  On-line CPU(s) list:    0-23
Vendor ID:                GenuineIntel
  Model name:             Intel(R) Xeon(R) w5-2455X
    CPU family:           6
    Model:                143
    Thread(s) per core:   2
    Core(s) per socket:   12
    Socket(s):            1
    Stepping:             8
    CPU max MHz:          4600.0000
    CPU min MHz:          800.0000
    BogoMIPS:             6384.00
    Flags:                fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic movbe popcnt t
                          sc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb cat_l3 cat_l2 cdp_l3 intel_ppin cdp_l2 ssbd mba ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb intel_pt avx512cd sha_ni avx512bw avx512vl xsaveopt xsa
                          vec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local split_lock_detect user_shstk avx_vnni avx512_bf16 wbnoinvd dtherm ida arat pln pts hwp hwp_act_window hwp_epp hwp_pkg_req vnmi avx512vbmi umip pku ospke waitpkg avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg tme avx512_vpopcntdq la57 rdpid bus_lock_detect cldemote movdiri movdir64b enqcmd fsrm md_cl
                          ear serialize tsxldtrk pconfig arch_lbr ibt amx_bf16 avx512_fp16 amx_tile amx_int8 flush_l1d arch_capabilities ibpb_exit_to_user
Virtualization features:  
  Virtualization:         VT-x
Caches (sum of all):      
  L1d:                    576 KiB (12 instances)
  L1i:                    384 KiB (12 instances)
  L2:                     24 MiB (12 instances)
  L3:                     30 MiB (1 instance)
NUMA:                     
  NUMA node(s):           1
  NUMA node0 CPU(s):      0-23
Vulnerabilities:          
  Gather data sampling:   Not affected
  Itlb multihit:          Not affected
  L1tf:                   Not affected
  Mds:                    Not affected
  Meltdown:               Not affected
  Mmio stale data:        Not affected
  Reg file data sampling: Not affected
  Retbleed:               Not affected
  Spec rstack overflow:   Not affected
  Spec store bypass:      Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:             Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:             Mitigation; Enhanced / Automatic IBRS; IBPB conditional; RSB filling; PBRSB-eIBRS SW sequence; BHI BHI_DIS_S
  Srbds:                  Not affected
  Tsx async abort:        Not affected
  Vmscape:                Mitigation; IBPB before exit to userspace
available: 1 nodes (0)
node 0 cpus: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23
node 0 size: 63802 MB
node 0 free: 55357 MB
node distances:
node   0 
  0:  10 
BOOT_IMAGE=/boot/vmlinuz-6.8.0-87-generic root=UUID=<redacted> ro quiet splash vt.handoff=7
analyzing CPU 5:
  driver: intel_pstate
  CPUs which run at the same hardware frequency: 5
  CPUs which need to have their frequency coordinated by software: 5
  maximum transition latency:  Cannot determine or is not supported.
  hardware limits: 800 MHz - 4.40 GHz
  available cpufreq governors: performance powersave
  current policy: frequency should be within 800 MHz and 4.40 GHz.
                  The governor "powersave" may decide which speed to use
                  within this range.
  current CPU frequency: Unable to call hardware
  current CPU frequency: 3.31 GHz (asserted by call to kernel)
  boost state support:
    Supported: yes
    Active: yes
```

</details>

<details>

<summary><strong>NICs: 3x BlueField-2 (2x25G)</strong></summary>

```sh
devlink dev info
pci/0000:06:00.0:
  driver i40e
  serial_number <redacted>
  versions:
      fixed:
        board.id 000000-000
      running:
        fw.mgmt 9.140
        fw.mgmt.build 76856
        fw.mgmt.api 1.15
        fw.psid.api 9.40
        fw.bundle_id 0x8000f09e
        fw.undi 1.3534.0
pci/0000:06:00.1:
  driver i40e
  serial_number <redacted>
  versions:
      fixed:
        board.id 000000-000
      running:
        fw.mgmt 9.140
        fw.mgmt.build 76856
        fw.mgmt.api 1.15
        fw.psid.api 9.40
        fw.bundle_id 0x8000f09e
        fw.undi 1.3534.0
pci/0000:4e:00.0:
  driver mlx5_core
  versions:
      fixed:
        fw.psid DEL0000000033
      running:
        fw.version 24.46.3048
        fw 24.46.3048
      stored:
        fw.version 24.46.3048
        fw 24.46.3048
auxiliary/mlx5_core.eth.0:
  driver mlx5_core.eth
pci/0000:4e:00.1:
  driver mlx5_core
  versions:
      fixed:
        fw.psid DEL0000000033
      running:
        fw.version 24.46.3048
        fw 24.46.3048
      stored:
        fw.version 24.46.3048
        fw 24.46.3048
auxiliary/mlx5_core.eth.1:
  driver mlx5_core.eth
pci/0000:85:00.0:
  driver mlx5_core
  versions:
      fixed:
        fw.psid DEL0000000033
      running:
        fw.version 24.46.3048
        fw 24.46.3048
      stored:
        fw.version 24.46.3048
        fw 24.46.3048
auxiliary/mlx5_core.eth.2:
  driver mlx5_core.eth
pci/0000:85:00.1:
  driver mlx5_core
  versions:
      fixed:
        fw.psid DEL0000000033
      running:
        fw.version 24.46.3048
        fw 24.46.3048
      stored:
        fw.version 24.46.3048
        fw 24.46.3048
auxiliary/mlx5_core.eth.3:
  driver mlx5_core.eth
pci/0000:bc:00.0:
  driver mlx5_core
  versions:
      fixed:
        fw.psid DEL0000000033
      running:
        fw.version 24.46.3048
        fw 24.46.3048
      stored:
        fw.version 24.46.3048
        fw 24.46.3048
auxiliary/mlx5_core.eth.4:
  driver mlx5_core.eth
pci/0000:bc:00.1:
  driver mlx5_core
  versions:
      fixed:
        fw.psid DEL0000000033
      running:
        fw.version 24.46.3048
        fw 24.46.3048
      stored:
        fw.version 24.46.3048
        fw 24.46.3048
auxiliary/mlx5_core.eth.5:
  driver mlx5_core.eth
```

</details>

### Results

Almost 13 gbps at 1360b packets in `XDP_COPY` mode:

```txt
AF_XDP TX:
iface=center_1 queue_id=0 dst_mac=<redacted> src_ip=192.168.1.10 dst_ip=192.168.1.20 dst_port=9000 count=100000000 pkt_size=1360 zerocopy=false
bound AF_XDP socket: ifindex=5 zerocopy=false
srcMAC=<redacted> dstMAC=<redacted>
finished: packets=100,000,000 | duration=1m26.277045439s | rate=1,159,056 pps | 12610.54 Mbit/s (1.6 GB/s)

real    1m26.930s
user    0m0.002s
sys     0m0.005s
```

Line-rate (~25 gbps) at 1360b packets in `XDP_ZEROCOPY` mode:

```txt
AF_XDP TX:
iface=center_1 queue_id=0 dst_mac=<redacted> src_ip=192.168.1.10 dst_ip=192.168.1.20 dst_port=9000 count=100000000 pkt_size=1360 zerocopy=true
bound AF_XDP socket: ifindex=5
srcMAC=<redacted> dstMAC=<redacted>
finished: packets=100,000,000 | duration=44.28407433s | rate=2,258,148 pps | 24568.65 Mbit/s (3.1 GB/s)

real    0m44.937s
user    0m0.001s
sys     0m0.005s
```

## Test Mode

You can run the benchmark in test mode that verifies the order and integrity of all packets.
I've been able to get 1 billion packets transferred without reordering in zerocopy mode,
but couldn't reproduce this result in copy-mode.
