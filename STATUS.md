# STATUS / 进度日志

> 防上下文压缩丢失的“单一事实源”。每次重要阶段更新本文件。
>
> 2026-10-30 清理：旧 v2/v3/v3b/v3c LK 与旧 payload 已删除。当前文件只用
> `dist/lk.img`、`dist/uefi.img`、`dist/uefi.fd`；
> FlashTool 侧短名 `lk.img` / `uefi.img` / `lk-recovery.img`。

## 2026-10-30 — v5 真机：UEFI 已启动（里程碑）

- 用户真机确认：刷 LK v5 + `fastboot boot uefi.img` 后 **UEFI 启动成功**，
  且 UEFI 侧出现 ADB/USB 端口（待确认 `adb devices` 是否可交互）。
- host 端 `fastboot boot` 会一直停在 `Booting`（不返回 OKAY）：LK 交棒后
  不再回 fastboot；UEFI 保持 USB 时 host 也等不到断开。Ctrl+C 即可。
- 生效配置：
  ```
  LK v5      sha256 6aea4c4258ac0f639e1ec2ce103db7b54eb607435173a26fb5f803e8e20a8ddd
  uefi.img   sha256 9b89578a61e7150ecbc7e84e17a66744fae7abef41294949c869cb2a262abdf6
  ```
  5 条补丁：0x81d8（boot stub）、0xd12c/0xd15c（skip loader）、
  0xc3f0（overlay 钩子）、0xcb7c（bootconfig 钩子）。
- 完整链路：`fastboot boot` → bootimg handler → skip storage loader →
  stock dtbo overlay（正确基址/尺寸）→ mb_dtb → mb_kernel
  (0x7c80000 @0x40000000) → gzip 解压 BootShim+FD 到 0x40000000 →
  io_task/set_fdt → `bootconfig skipped` → SMC 0xC2000115 →
  BootShim 搬 FD 到 0x50000000 → UEFI PrePi。
- 待补充（下一步记录）：屏幕停在哪个阶段（DEBUG 日志/BDS/Shell）、
  是否稳定不重启、UFS/显示/触控等外设状态。

## 2026-10-30 — v5：bootconfig 追加跳过（已构建/仿真，待刷写）

- v4 真机 22:29（未加 gap 镜像）已打通 overlay：
  - `overlay base=0x80704810 size=0x50d3c` → `after overlay, fdt size(558491)`
    （= 0x50d3c + 0x3785f），`DT overlay ok`；
  - mb_kernel 0x40000000 分配、解压 15 ms、io_task/set_fdt 全部通过
    （model=MT6896Z/CZA，panel nt36672c）；
  - 新阻塞：LK 在 `boot_linux_fdt` 末尾把 bootconfig 追加到
    `0x66f00000 + vendor ramdisk size`（vendor ramdisk 区）。该区只有
    storage loader 会映射，fastboot 路径未映射 →
    `data fault PC 0x…6bf6c FAR 0xffff000066f00000`。
- v5：补丁 `0xcb7c 0x97fff896 → 0x97ffd3bf`（`bl 0xadd4` →
  `bootconfig_hook`）。钩子 magic 命中时跳过 bootconfig、返回 0 字节
  （调用方 `linux,initrd-end = w23+w22+w0` 保持原值）；正常 boot 原样
  尾调用 0xadd4。
- 成品：
  ```
  dist/lk.img v5  16,777,216 B
  sha256 6aea4c4258ac0f639e1ec2ce103db7b54eb607435173a26fb5f803e8e20a8ddd
  dist/uefi.img  1,091,584 B（不变）
  sha256 9b89578a61e7150ecbc7e84e17a66744fae7abef41294949c869cb2a262abdf6
  ```
- payload 1744 B（0x1880..0x1f50）：`overlay_hook 0x18f8`、
  `bootconfig_hook 0x1a78`、`boot_handler 0x1acc`、`magic 0x1f40`。
  5 条补丁：0x81d8/0xd12c/0xd15c/0xc3f0/0xcb7c。
- 仿真：`emulate_payload.py` 新增 bootconfig 用例（normal 透传 / magic
  跳过）；`make verify` 全通过。
- **未刷写**。下一步：刷 `images/lk-v5.img` 后
  `fastboot boot ...\uefi.img`；期望在 set_fdt 之后出现
  `kaeru-rawboot: bootconfig skipped`，随后进入 SMC。若仍有 fault，
  记录 PC/FAR 与最后一条 hook 日志。

## 2026-10-30 — v4：magic 覆盖 dtb_size 的真凶 + kernel_addr 修正（已构建/仿真，未刷写）

- v3f 真机 expdb 结论（21:41）：
  - 钩子生效：`kaeru-rawboot: no fdt for overlay, skipped`；
  - 下游 `DT overlay ok, fdt size(4194304)`；
  - 新阻塞：`mblock_alloc ... name:mb_kernel sz:0x7c80000 expect 0x40080000`
    `cannot find a target` → `mt_boot.c:622 kernel_addr ... is not taken from mb`。
- **真凶**：v2/v3f payload 的 magic 在 `g_boot_info+0x668`，16 字节覆盖到
  v2 头 `dtb_size`(+0x670) 和 `dtb_addr`(+0x674)。`dtb_size` 变成
  `"-BOO"` = **0x4F4F422D**，所以：
  - 任何 DTB 内容都不可能通过 overlay 的 size 检查（`Bad fdt size`）；
  - v3f 钩子按 `totalsize==w27` 扫描必然失败（w27 被污染）；
  - 之前的 `x26=0xba800 vs DTB 0xb9800` 是真实布局差异，但不是唯一原因。
- v4 改动：
  1. magic 迁到 **LK+0xf3100**（vendor_boot header 拷贝区 +0x258；
     ANDROID! 镜像路径不写该区，g_boot_info 保持完整）；
  2. 钩子日志加上 base/size：`overlay base=0x%x size=0x%x`、
     `no fdt for overlay (base=… size=…)`；
  3. 镜像 `kernel_addr` 改为 **0x40000000**：LK 的 `mb_kernel` 固定申请
     0x7c80000，必须与 mblock 空闲区起点一致；`vm_kernel` 映射与 SMC
     入口也都用该地址；
  4. `uefi.img` **不加** DTB gap：真机 v4 expdb 证明 x26 =
     `download+0xb9800` = kernel 后紧接的 DTB（LK 没有额外加页）；
     padded 镜像反而让 x26 指向零区。
- 成品：
  ```
  dist/lk.img v4  16,777,216 B
  sha256 2bcae5f196ca079d0625f3d3dfad084642a28fe27eb5d6f4e6c2ddec5a483e82
  dist/uefi.img   1,091,584 B (kernel_addr=0x40000000, DTB 紧接 kernel)
  sha256 9b89578a61e7150ecbc7e84e17a66744fae7abef41294949c869cb2a262abdf6
  ```
- payload 1624 B（0x1880..0x1ed8）：`overlay_hook 0x18f8`、
  `memmove_up 0x1a3c`、`boot_handler 0x1a78`、`magic 0x1ec8`。
  补丁与 v3f 相同（0x81d8/0xd12c/0xd15c/0xc3f0）。
- 仿真新增回归断言：magic 不得落在 g_boot_info 0x67c 字节内，且应在
  vendor header 拷贝区。`make verify` 全通过（含真实 uefi.img）。
- **v4 真机第一次（22:23，padded 镜像）**：magic 修复生效（size=0x50d3c），
  `mb_kernel` 分配/解压成功；但 x26 实测为 `download+0xb9800`，padded 的
  DTB 在 0xba800 → `no fdt` skip，vm_dtb 留旧 DTB，随后
  `kernel_dts_mblock_conflict_check` 失败。改用未加 gap 的 uefi.img
  （9b89578a）即可命中 overlay，**无需再刷 LK**。
- 下一步：`fastboot boot ...\uefi.img`（9b89578a）；期望
  `overlay base=0x… size=0x50d3c` → `after overlay, fdt size(~533882)`
  → `DT overlay ok` → mb_kernel/解压 → io_task/set_fdt → SMC。

## 2026-10-30 — v3f：bootimg overlay 钩子 + 根因更正（已构建/仿真，未刷写）

- **根因更正（决定性）**：`mb_dtb` 其实分配成功。v3e expdb 明确有
  `mblock_alloc_range_no_lock: start: 0x47c80000, sz: 0x400000 ... name:mb_dtb`，
  随后才 overlay 失败。真正原因是 **v2 boot 路径的基 DTB 指针算错**：
  LK `boot_linux_fdt` 对每个 0 长度段（ramdisk / recovery_dtbo）仍各加 1 页，
  x26 = `img + 0x800 + align(0xb8a30) + 0x800 + 0x800` = 镜像内 **0xba800**，
  而实际 DTB 在 **0xb9800**（正好早 0x1000）。`[0xba804]` 读到 27 而不是
  `0x50d3c` → `ufdt_apply_overlay(): Bad fdt size!`。
- 换 DTB 内容无用；**偏移**才是问题。
- 离线复核：`dist/uefi.img` 内嵌 stock vendor FDT（0x50d3c）+ stock
  `dtbo_a` entry（0x3785f）→ `fdtoverlay` 合并成功，533,882 B
  （totalsize 0x8257a）。
- **LK v3f 实现**：payload 新增 `overlay_hook`（0x18f8），把 0xc3f0 的
  `bl 0x72700` 改为 `bl overlay_hook`：
  - magic 未命中（正常 boot）：原参数尾调用 stock `0x72700`，逻辑不变；
  - magic 命中（RAWBOOT-UEFI）：
    1. 从 x26 起向前最多 0x4000 字节扫描 FDT magic + `totalsize == w27`；
    2. 命中则用该基址调用 stock overlay（与正常 boot 同一条合并路径）；
    3. overlay 失败则跳过，把 FDT 拷到 LK 原来的 x26 槽位并 `*out=x26`，
       避免下游 `free()` 非堆指针；返回 0 让流程继续；
    4. 扫不到 FDT 则跳过 overlay、保留原指针并返回 0。
- 补丁（输入 `os3-unlockless/lk.bin`）：
  ```
  0x81d8  0x17fff284 -> 0x17ffe5aa  b  0x1880   (原有)
  0xd12c  0x94011236 -> 0x97ffd1df  bl 0x18a8   (原有)
  0xd15c  0x9401122a -> 0x97ffd1d3  bl 0x18a8   (原有)
  0xc3f0  0x940198c4 -> 0x97ffd542  bl 0x18f8   (v3f 新增)
  ```
- payload 1600 B（0x1880..0x1ec0，cave 上限 0x2400）；符号：
  `overlay_hook 0x18f8`、`memmove_up 0x1a30`、`boot_handler 0x1a6c`、
  `magic 0x1eb0`。
- 成品：
  ```
  dist/lk.img  v3f  16,777,216 B
  sha256 9007e078f5f6a8ea2b3d3fdb3f1b8072198a90b6922262264cacb1c213d2df6b
  dist/uefi.img（不变）1,091,584 B
  sha256 b15e446fc30de979ac9663ca45e6e6219ef48d22430f1ee2ae0d30600902c4cb
  dist/uefi-pad.img（可选，不改 LK 的兼容镜像）1,095,680 B
  sha256 9b138fe729b9194f8399a9703b447b75255b99dc92e80567efdf9970e6a9f71c
  ```
- `uefi-pad.img` = 原 uefi.img 在 kernel 与 DTB 之间插入 0x1000 零填充
  （`make_bootimg_v2.py --dtb-gap 0x1000`），使 stock v2 路径的 x26 直接
  指向 DTB；可在**当前 v3e** 上直接 `fastboot boot` 验证，无需刷 LK。
- 仿真（`make verify` 全通过）：
  - `emulate_overlay.py`：真实 LK 0xc3dc..0xc3f4 + v3f payload；
    正常放行、-0x1000 纠正、overlay 失败回退拷贝、无 FDT 跳过、
    真实 uefi.img（0xba800→0xb9800）、padded uefi.img 六组用例通过；
  - `lk_sim.py` 增加 0xc3f0 目标检查；镜像/CERT2/未变子分区校验通过。
- **未刷写**。下一步真机（二选一，先选 A 可零刷写验证）：
  - A：v3e + `fastboot boot uefi-pad.img`；期望 `after overlay, fdt size(...)`
    后进 SMC/BootShim；
  - B：刷 v3f 后 `fastboot boot uefi.img`（原 b15e446f）；期望日志
    `kaeru-rawboot: overlay base fixed 0x…` → `after overlay`。
  - 失败看：`overlay failed, skipped` 后是否继续；或 SMC/看门狗复位。

## 2026-10-30 — v3e：改走 LK 正常 boot 路径（v2 bootimg）

> 明确状态：**UEFI 尚未启动**。最近一次是 LK 自己的 boot 路径处理我们的
> gzip BootShim+FD（kernel_sz=0xb8a30），storage loader 已跳过；停在
> stock dtbo_a overlay，未跳 kernel/SMC。

- v3d Stage0+DTB（原地 BL33、x2=0x47c80000）仍复位 → BL33 入口被 ATF/GZ
  拒绝；手动复制 0x40080000 也不可行（低/高 VA 均未映射）。
- v3e：自制**合法 v2 boot image**（`uefi.img`）：
  - kernel = gzip(BootShim+FD)，kernel_addr=0x40080000；
  - dtb = lk_main_dtb.bin，dtb_addr=0x47c80000；
  - name="RAWBOOT-UEFI"。
  LK handler 识别 name 后走 `load_bootinfo → bootinfo_set_image →
  boot_linux_from_storage`；magic 让 load_wrapper 跳过 storage loader；
  LK 自己解压/映射 kernel 并调 SMC。
- 成品：
  ```
  lk.img    0fc3cd80be314d496df381982874e5bce4414ed387579db4ed4dc85b0ab9a341
  uefi.img  461cdefc4d830b69cd0b2999c85acabd5feef665699a4236560b45f6b583d9a2
  ```
- 仿真：bootimg handler（load_bootinfo/set_image/boot_from_storage、magic
  skip）、raw/wrapped 路径、CERT2/part 全部通过。
- 真机结果：host 未再 creating boot image（合法 v2 image），但 LK 在
  `mt_boot.c:890` 断言 `ramdisk_target_addr != 0`。boot header 的
  `ramdisk_addr` 原为 0；已改为 `0x51000000`（size 仍 0），只换 uefi.img，
  不用再刷 LK。
- 新 uefi.img：`1c934ccbb5217aea59c7e2269d4006565d832497ae405fe3603f52b224eca441`。
- 真机第二步（ramdisk_addr=0x51000000）：已过 ramdisk 断言，进入
  `boot_linux_fdt`；随后 stock `dtbo_a` overlay 我们的 `lk_main_dtb` 报
  `ufdt_apply_overlay():Bad fdt size!`，`mt_boot.c:587 err == NO_ERROR`
  断言。基 DTB 必须是 stock vendor_boot DTB。
- 已 dump `vendor_boot_a`/`dtbo_a`：从 vendor_boot (v4, page 4096,
  dtb_size 0x50d7c) 提取 stock FDT **0x50d3c**（model MT6895）；
  `fdtoverlay` 对 stock `dtbo_a` 离线验证成功（merged 533,882 B）。
- stock DTB 重打 `uefi.img`（b15e446f…）再测：仍 `Bad fdt size`。对比正常
  boot 日志：正常 boot 在 `boot_linux_fdt` 里先 `mblock_alloc ... name:mb_dtb`
  并拷贝 DTB，再 overlay 成功（`after overlay, fdt size(556975)` =
  lk_main_dtb 0x50750 + dtbo 0x3785f）；我们的 bootimg 路径没有 `mb_dtb`
  分配/拷贝，overlay 基 DTB 指针/尺寸无效。
- 结论：换 DTB 内容无效；需让 boot 路径用合法基 DTB 或跳过 overlay。
  下一步 v3f：overlay 包装函数 `0x72700`、调用点 `0xc3f0`（x26=base,
  w27=size），在 bootimg magic 下改用 `lk_main_dtb`（0x50750）并跳过
  overlay；正常 boot 保持原逻辑。
- 待再测：`fastboot boot uefi.img`（v3f 刷入后）。

## 2026-10-30 — v3d 真机：0x40080000 低/高都未映射 → Stage0+DTB 测试

- v3d Stage0 expdb：
  ```
  kaeru-rawboot: host boot.img page=0x800
  kaeru-rawboot: copy payload pa=0x40080000 va=0x40080000
  data fault: PC at 0xffff00008006bf6c, FAR 0x40080000, iss 0x44
  ```
  `vmm_get_va(0x40080000)` 返回 0，低 identity 也未映射；复制到 0x40080000
  当前不可行。
- 生成 `stage0-dtb.img`（1 MiB，load=0 原地，dtb=0x47c80000）：
  ```
  sha256 fa0989254cd8b5d89328a4917c9472a8e6fda0c9768c078937c4b9f674a841ef
  ```
  不需要再刷 LK，v3d 直接在 BL33 入口调 SMC，x2 用 LK 已加载的合法 DTB。
- 结果判断：
  - 纯色 = BL33 入口 + DTB 被 ATF/GZ 接受；接着做 in-place 完整 UEFI；
  - 无颜色/复位 = BL33 入口仍被拒；转 LK 正常 boot 路径（v2 boot img +
    skip loader）或真 vmm 映射。

## 2026-10-30 — v3d：v3c 高 VA 写 fault → vmm_get_va + 低 identity

- v3c Stage0 真机 expdb（决定性）：
  ```
  kaeru-rawboot: host boot.img page=0x800
  kaeru-rawboot: copy payload pa=0x40080000 va=0x40080000   (%x 只打印低32位)
  data fault: PC at 0xffff00008006bf6c, FAR 0xffff000040080000, iss 0x46
  panic (caller 0xffff00008000125c): die
  ```
  即 handler 已解析 wrapped boot.img，`lk_memcpy` 写高线性 VA
  `0xffff000040080000` 时 translation fault——fastboot 下该 PA 没有高 VA 映射。
- v3d：不再硬编码高 VA。handler 调 LK `vmm_get_va(0x40080000)`：
  有映射用返回 VA；无映射退回低 identity `0x40080000`。复制后 SMC 入口
  仍为 `0x40080000`。
- 新 LK：
  ```
  LK v3d  a61598d0a04abddccb2645e18a471baa6ba722a2f00739020dc0876b399f2519
  ```
  Stage0/Full payload 不变（2ddfaae1… / 770e2378…），与 v3d 兼容。
- 仿真通过：vmm_get_va=0 → 低地址复制 → SMC x2=0x40080000 → BootShim →
  FD 0x50000000 → PrePi 0x500085A0；vmm 返回高 VA 的分支也测过。
- 待真机：刷 v3d，发同一个 `stage0.img`。
  - 纯色 = 成功；
  - data fault FAR=0x40080000 = 低 identity 也未映射 → 下一版用
    `vmm_alloc_physical`/DTB 区或 LK 正常 boot 路径；
  - 无 fault 但无颜色 = 复制成功、SMC 仍有问题 → 查 DTB/ATF 参数。

## 2026-10-30 — v3c：Stage0 真机无颜色/复位 → copy-to-0x40080000

- 用户已刷 v3b，发送 1 MiB Stage0（host 包装 0x800 页）后：**屏幕无变化，
  panic 复位**。判断 SMC 在下载缓冲区（BL33）入口被 ATF/GZ 拒绝，或
  payload 未执行。
- v3c：RAWBOOT 头读 `load_addr`；非 0 时 handler 先把 payload 复制到
  标准 kernel 区（高线性 VA `0xffff000000000000+PA`），再用
  `0x40080000` 调 `0x1CA10`/SMC；`load_addr=0` 仍保留原地路径。
- 新成品：
  ```
  LK v3c           6fe551c7a629385539d2023eef7c634533d3ef7a8726cebd2fe1702423c1f1be
  Stage0 v3c       2ddfaae1301de4f54570df61a6cdc407709abd3c10ec172ecfd1002204b8f7d1  (1 MiB, load=0x40080000)
  Full UEFI v3c    770e2378b1b3cff64ce7da74bee201d1fdf7fc3bdec75099c97bc9b856866785
  FD               7f6ca27d59e4bac7040b6ce05f34c14779d9209e22263fed313416fe29b40adc
  ```
- 仿真通过：wrapped boot.img → RAWBOOT → lk_memcpy 到
  `0xffff000040080000` → SMC x2=0x40080000 → BootShim → FD 0x50000000 →
  PrePi 0x500085A0。
- 旧 v3b 及其 payload 已移入 FlashTool
  `images/_archive_lk_old_20261030/`；当前只用
  `LK-UEFI-v3c-FLASH-THIS-16MB.img` +
  `fastboot_boot_work/stage0.img`。
- 待用户：刷 v3c，发 Stage0 v3c：
  - 整屏红/绿/蓝 = SMC/复制成功（颜色=EL）；
  - 无颜色 = 看 expdb 是否有 `kaeru-rawboot: copy payload pa=0x40080000 ...`；
    有则复制/入口仍失败，下一版改低地址 identity 或 vmm 映射。

## 2026-10-30 — UEFI RAWBOOT 成品：LK v3 + iQOO Z8 FD（待用户刷写）

### 成品（dist/）

```
iqooz8-os3-rawboot-uefi-16MB.img  16,777,216 B
sha256 0682bbb723732339dac78389a178a7a394b65f96bd76a1b2934a6620606977da
uefi-rawboot-iqooz8-debug.img     7,340,296 B
sha256 180857ca803da0539a3ebba866c1e3dc428ddf99a591c995cbe3ccf1c685606c
iqooz8-uefi-debug.fd              7,340,032 B
sha256 7f6ca27d59e4bac7040b6ce05f34c14779d9209e22263fed313416fe29b40adc
BootShim.bin 224 B sha256 e8ddb4cba383f5b7aa915d5c61ca3f226d45ed6f54642ec831b0e3cf12c1bb60
```

### LK v3b

- payload 由 v2 的 Android fastboot boot 改为 **RAWBOOT**（583 B，
  0x1880..0x1Bxx）；同时兼容 platform-tools 自动包的 `ANDROID!` boot.img
  （kernel 在 page_size，通常 0x800）：
  - 校验 `"RAWBOOT!"` + 0x28 头（load/entry/dtb/payload_size）；
  - 原地执行（下载缓冲 +0x28），不复制；
  - `clean_cache` 后调用 LK `0x1CA10`（x0=0xD0C8 SMC 桩 VA、
    x1=0xC2000115、x2=入口、x3=DTB、x4=0）；由 trampoline/ATF 进入 payload；
  - magic/size 错或 SMC 返回时打印 `kaeru-rawboot:` 并回 fastboot。
- 0xD12C/0xD15C 仍尾调用 stock storage loader，正常开机不变。
- `make verify` 全通过（CERT2/part/补丁/payload/注册/RAWBOOT 仿真）。

### iQOO Z8 UEFI（DEBUG）

- 新 `Platforms/Xiaomi/iqooz8Pkg`（复用 MT6895Pkg）：12G 内存图按真实
  mblock 重建；FB 0xFE20F000/1088x2388/3 层；GIC/UFS/OVL/WD/PMIF 按
  MT6896；PrePi 早期关看门狗（str 0x22000000 → 0x1C007000）。
- DEBUG 构建：DXE 全局 SerialPortLib = FrameBufferSerialPortLib（日志上屏）；
  PrePi 仍 UART。首版剔除 UFS/SCSI/ext4，避免存储初始化卡住 BDS。
- FD PrePi entry 0x500085A0；FD base 首指令 `b 0x85A0`。
- 端到端仿真 `scripts/sim_rawboot_uefi.py`：真实 payload → handler →
  `0x1CA10` 参数 → BootShim → FD 复制到 0x50000000 → PrePi entry。
- 已复制到 FlashTool images：
  `images/lk_rawboot_uefi_16MB.img`、
  `images/fastboot_boot_work/uefi_rawboot.img`。

### 真机第一步结果 / 修复

- 用户已刷 v3 并执行 platform-tools `fastboot boot uefi_rawboot.img`：
  host 打印 `creating boot image...`（自动包成 boot.img），随后
  `Booting FAILED (remote: 'unknown reason')`；设备仍在 fastboot。
- 根因：host 包出的镜像开头是 `ANDROID!`，v3 只认裸 `RAWBOOT!`，handler
  返回 bad magic。已出 **v3b**：识别 `ANDROID!` + page_size，从 +0x800
  找到 RAWBOOT；裸 RAWBOOT 仍支持。
- v3b 已过仿真（wrapped 用例 entry=DL_BUF+0x800+0x28 → BootShim →
  PrePi 0x500085A0）。payload/FD 未变。

### 待真机（用户执行）

1. 刷 `lk_rawboot_uefi_v3b_16MB.img` 到 lk_a；
2. 再执行 `fastboot boot uefi_rawboot.img`；
3. 预期同前。

## 2026-10-30 — UEFI 专项：路线决策与 pearl EDK2 构建/仿真

- 新增 `docs/10-uefi-rawboot-decision.md`。结论：iQOO Z8 走
  **LK RAWBOOT → ATF SMC 0xC2000115 → BootShim + pearl MT6895 EDK2**，
  不做 Camellia 式 Linux→UEFI 热跳。
- 新逆向证据：LK `boot_linux_fdt` 末尾调 `0x1CA10`，经 quiesce、关 cache、
  `0x1C7C8` trampoline，用 `0xD0C8` 桩执行 `SMC 0xC2000115` 交 ATF
  （x1=入口、x2=DTB、x4=1），与 degas 文档一致。RAWBOOT 可直接复用。
- 平台实测：MT6896 DRAM 12GiB（0x40000000..0x340000000）；LK mblock
  24 项已从 expdb 还原；`0x40000000..0x50700000` 与 pearl 内存图逐项同址。
  FB 0xFE20F000/0x1DF0000（1080×2388，pitch 1088，3 层）。
- pearl EDK2 本地构建成功（edk2@5801910 + 补齐 BaseVariableFlashInfoLib/
  brotli v1.1.0/jansson v2.14；clang18 修 ASLCC 与 GCC13 警告）：
  `PEARL_UEFI.fd` 7,340,032 B，sha256 `6d943027…cc36626`；
  PrePi entry 0x50007560；FD base = `b 0x7560`。
- BootShim 144 B，sha256 `cdda42fa…28ac8f3`；shim+FD 7,340,176 B，
  sha256 `7eb7ee52…f70235`。`scripts/sim_bootshim.py` Unicorn 仿真：
  FD 复制到 0x50000000，最终 PC=0x50007560。
- 关键风险：degas 无喂狗 ~33.6s 复位，Camellia “30s 复位”疑为看门狗；
  iQOO 看门狗 0x1C007000。另有 SMC 一次性/GZ、EL1/EL2、carveout 不完整。
- 未刷写；下一步：生成 MT6896/iqooz8 平台包与 RAWBOOT 分支，先做
  lk_sim/Stage-0 小桩，再讨论真机。

## 2026-10-30 — v2 修复首次真机 NX 事故（当前成品）

### 产物

```
dist/iqooz8-os3-fastboot-boot-16MB.img
size   16,777,216
sha256 984c2f60d4b0ea02084acb56632f278fed49258fd73325fc8426e48af4a90018
payload 822 B (0x336), sha256 08ad4906ecc0ec606cfd763b3f824325921c61d40261ae02448ee6ffd265fc92
```

输入：`os3-unlockless/lk.bin`
sha256 `034d97fa...d2d0b`；CERT1/CERT2 外部验证 VALID。

### 首次真机（v1）事故与根因

- v1 把 payload 放在 lk 数据尾部 0xcef90。
- expdb：
  ```
  [SEC] lk cert chain vfy pass
  [SEC] image lk header auth pass
  [SEC] image lk auth pass
  notify_enter_fastboot / starting app fastboot
  instruction abort: PC at 0xffff0000800cef90
  panic (caller 0xffff00008000125c): die
  ```
- 0xffff0000800cef90 = LK_base + 0xcef90 = v1 payload 第一条指令。
- 证书/刷写无误；LK 把镜像数据尾部映射为不可执行（NX），fastboot init
  执行注册函数尾 0x81d8 -> 0xcef90 时取指异常，panic，无法进 fastboot。
- 详见 `docs/07-expdb-root-cause-and-fix.md`。

### v2 修复

- 把 payload 移到 **0x1880**：VBAR_EL1=0x1000 的向量表之后、0x187c..0x2400
  全零洞内；与向量同页（0x1000..0x1fff，已证明可执行），无代码/数据/字面量
  引用。
- payload 822 B，0x1880..0x1bb6；代码+字符串均在同一可执行页内；
  **lk dsize 保持 0xcef90**，不再扩展镜像/数据尾部。
- 新符号：stub 0x1880、wrapper 0x18a8、handler 0x18f8、boot_cmd 0x1a58、
  magic 0x1a60。
- 补丁：
  - 0x81d8 `0x17fff284` -> `0x17ffe5aa` (b 0x1880)
  - 0xd12c `0x94011236` -> `0x97ffd1df` (bl 0x18a8)
  - 0xd15c `0x9401122a` -> `0x97ffd1d3` (bl 0x18a8)
- 原 6 条 fastboot 命令不变；`boot` flags (1,0)；正常启动 wrapper 无 magic
  时尾调用原 storage loader。
- 日志：`kaeru-fb-boot:` 前缀，经 LK printf 进入 log/expdb。

### 验证（本地，无刷写）

- `verify_output.py`：PASS；lk dsize 0xcef90；cave 0x1880..0x1bb6；
  原 6 条命令/未变子分区/CERT2 全链 OK；输出 sha 984c2f60...
- 外部 `verify_mtk_image.py`：CERT1/CERT2 signature OK、image header/data
  hash OK、Result VALID。
- `emulate_payload.py`：stub/wrapper/handler 控制流、magic、日志、清理 PASS。
- `lk_flow_sim.py`：Unicorn 从成品执行真实 0x8120 -> 0x81d8 -> 0x1880；
  原 6 条命令保留、boot 头插；locked 下 boot 可达；PASS。
- `lk_sim.py`（新增，汇编级 RX/RW 权限）：
  - 按 [0,0xb1000) RX、[0xb1000,0x1000000) RW/NX 映射；
  - 正向：真实 0x8120 -> 0x81d8 -> 0x1880，7 条注册、boot handler 0x18f8；
  - 负向 v1：分支到 0xcef90（RW/NX）→ `UC_ERR_FETCH_PROT`，PC=0xcef90，
    精确复现 expdb；
  - wrapper/handler 在 RX 代码页执行，RW 只写 globals；PASS。
- 代码洞静态检查：输入 0x1880..0x1bb6 全零；无 ADRP/ADR/BL/B/LDR-literal
  或 relocation 指针引用。

### 待真机验证

1. 当前设备仍是 v1（fastboot 不可用）；先用已知良好的 LK（例如
   `images/lk_os3_setactive_keyswap_16MB.img`）通过 FlashTool/BROM 恢复。
2. 刷入 v2 `images/lk_os3_fastboot_boot_16MB_v2.img` 到 `lk_a`。
3. 验证：原 fastboot 命令 → `fastboot boot boot.img`。
4. 若仍异常，回读 expdb：
   - PC 若为 0x…001880/0x…0018xx，说明代码页执行权限仍不符（需页表/换洞）；
   - 若进入 fastboot，看 `kaeru-fb-boot:` 与 `storage loader ret=`。

### 文档 / 仓库

- `docs/01` 布局；`02` fastboot；`03` 启动流程；`04` 实现；`05` kaeru；
  `06` 运行全景；`07` expdb 事故与修复；`08` 汇编级 RX/RW 模拟器。
- `notes/function-map.md` 偏移表。
- 外部项目 `tools/lk-patcher-master` 用于容器/CERT2 重签。

### 历史

- v1（payload @0xcef90）已真机证明 NX 崩溃，产物不再使用。
- v1 的旧哈希 73430131 / 27206f50 仅作历史记录。


## 2026-10-30 — v2 真机第二步：fastboot boot 已进 handler，stock AVB 崩

- **好消息**：v2 能进 fastboot；官方 fastboot 的 `download:`/`boot` 都成功；
  expdb 出现 `kaeru-fb-boot: start size=0x6000000`，NX 修复有效。
- **本次失败点**：handler 先调 `storage_image_loader(0)`，在 locked 下：
  - `check_device_unlock_auth` 失败，`AVB: force img_auth_required = 1`；
  - `boot_b: Hash of data does not match digest`（boot 分区被改过）；
  - `heap_grow` 失败 + `avb_util Failed to allocate memory`；
  - `avb_slot_verify` 返回 NULL，LK 0x16dbc 未判空 `ldr x8,[x0,#16]` →
    data fault FAR 0x10 → panic/HALT。
- **不是** NX/命令/CERT 问题；host 的 `Booting FAILED (Status read failed)` 是
  设备 panic 断开。
- **下一步**：
  - UEFI/XNU：新增 RAWBOOT 分支，跳过 storage loader/AVB，复制到 load_addr、
    flush cache、跳 entry；格式见 `docs/09-fastboot-boot-realdevice-avb.md`。
  - Android Magisk：需要跳过 loader/AVB 或应用 `avb_allow_error`，并处理
    v4 vendor_boot。
- 新增文档 `docs/09-fastboot-boot-realdevice-avb.md`。


## 2026-10-30 — 交接日志

- 已写入 `HANDOVER.md`：LK v2 成果/两次真机事故、设备/文件状态、UEFI/XNU 项目
  调研（HakiOS MT6768、Camellia MT6833、CrackerCat MT6895、Xiaomi 14T MT6897
  等）和下一步。
- 新对话请先读 `HANDOVER.md`，再读 `docs/07`、`docs/09`。
