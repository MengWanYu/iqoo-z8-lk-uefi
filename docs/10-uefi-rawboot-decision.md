# 10. UEFI bring-up 路线决策：LK RAWBOOT → ATF SMC → pearl EDK2

> 2026-10-30。基于 `HANDOVER.md`、`docs/09`，新增对 pearl MT6895 EDK2、
> Camellia MT6833、Xiaomi 14T MT6897 的源码/真机资料分析，以及本仓 LK 的
> 最终启动路径逆向。**本文只做分析与本地构建/仿真，不刷写。**
>
> 实现成品与刷写说明见 `docs/11-rawboot-uefi-flash.md`；本文保留路线分析。

## 0. 一句话结论

iQOO Z8（MT6896/D8200）走 **LK RAWBOOT 直接启 UEFI**：
fastboot `boot` 下载 payload → handler 跳过 storage loader/AVB → 把
`BootShim + pearl MT6895 EDK2 FD` 复制到 `0x40080000` → 调用 LK 自己的
最终启动函数 `0x1ca10`（quiesce → 关 cache → SMC `0xc2000115` 交给 ATF）
→ ATF 进入 `0x40080000` → BootShim 把 FD 搬到 `0x50000000` 并跳到 PrePi。
**不采用 Camellia 的 Linux→UEFI 热跳**：它需要带 `jump2`/`camellia_jump_to`
的自编译内核和匹配 KO，iQOO 无对应内核源码/补丁，且其 UEFI 没有 UFS DXE；
而 iQOO 的 `fastboot boot` 已经可用，LK→ATF→UEFI 的交接方式已在
MT6897（degas）上真机证明，pearl 提供了 MT6895 同族、可本地构建的
EDK2 基线。

## 1. 三个参考项目的实测结论

| 项目 | 平台 | 启动链 | UEFI 运行级 | 存储/显示 | 真机状态 |
|---|---|---|---|---|---|
| CrackerCat `EDK2-Xiaomi-MediaTek-MT6895` (pearl) | Redmi Note 12T Pro, MT6895 | 设计：LK 解压 boot.img kernel → BootShim@0x40080000 → 复制 FD 到 **0x50000000/0x700000** → PrePi | PrePi 有 EL1/EL2 分支（EL2 时设 HCR_TGE、CNTHCTL）；degas 实测被 GZ 降到 EL1，EL2 路径需实测 | `MtkUfsDxe`（UFSHCI 0x112b0000，仅补 XOUFS CLK_CG，依赖 LK 已初始化 PHY/链路）；`SimpleFbDxe` 直接接管 OVL 0x14002000/0x14003000 | 作者 WIP（UFS host/ACPI/ext4/keypad），无 README/release/公开真机记录；**本次本地构建成功** |
| Camellia `uefi-camellia` | Redmi Note 10 5G, MT6833 | Linux → 最小 initramfs → `drm_linear` → `uefi_jump.ko` → UEFI（FD 基址 **0xA0000000**，栈 **0xA0200000**） | 由内核 `camellia_jump_to()` 关闭 MMU 后跳入 | 无原生 UFS DXE；framebuffer 用散页映射 + 线性 shadow | 热跳已硬件验证；`fastboot boot` 本机不可用；“LK 直接 BootShim/UEFI”约 30 秒复位，已放弃 |
| `Port-woa-uefi-Xiaomi-14T` (degas) | Xiaomi 14T, MT6897 | LK 加载 wrapper@0x40000000 → FD@**0x40200000** → ATF SMC `0xc2000115` 进入；刷 `boot_<slot>` | 实测 **EL1**（GZ 把 ATF 的 EL2h `0x3c9` 改成 EL1h `0x3c5`）；`HCR_EL2.VM=1` | UFS 同一 `0x112b0000`，继承 LK PHY；显示继承 LK command-mode scanout，GOP BLT 后写 4 个 DSI mutex trigger | 8 核、显示、触控、UFS 读写已工作；无 Linux 中转 |

关键旁证：degas 首个无喂狗探针在 uptime **约 33.6 秒**被硬件看门狗复位。
Camellia “LK 直接执行 UEFI 约 30 秒固定复位”很可能也是看门狗，而非 EL/MMU。
iQOO Z8 的看门狗在 `0x1c007000`（与 pearl 相同），必须喂狗或关闭。

## 2. MT6896 平台实测约束

来源：`lk_main_dtb`（从 LK 容器 `lk_main_dtb` 子分区解出，model=`MT6895`）
+ 最近一次 v2 `fastboot boot` 的 expdb。

### 2.1 DRAM 与 LK 保留区（expdb `dump mblock info` / `mblock-R[*]`）

- DRAM：`0x40000000..0x340000000`，**12 GiB**（mblock[0] 6G + mblock[1] 6G）。
- LK 自身/BL33：`0x80000000..0x96000000`（`BL33-reserved`，352 MiB）；
  LK 镜像在 `0x80000000`，VA = `0xffff000000000000 + PA`。
- 关键保留（真机日志）：

| 名称 | 地址 | 大小 |
|---|---|---:|
| aee_debug_kinfo | 0x48080000 | 0x10000 |
| pstore | 0x48090000 | 0xe0000 |
| minirdump | 0x48170000 | 0x10000 |
| BL31-reserved | 0x48200000 | 0x200000 |
| crypto_hw | 0x48401000 | 0x1000 |
| pl-drambuf | 0x48500000 | 0x100000 |
| pl-boottag | 0x48600000 | 0x100000 |
| aee_lk | 0x50700000 | 0x800000 |
| TEE | 0x70000000 | 0x6200000 |
| SPM | 0x77FF0000 | 0x10000 |
| tee-secmem | 0x7BE00000 | 0x700000 |
| MCUPM | 0x7C500000 | 0x100000 |
| mtksmmu_protpgd | 0x7C600000 | 0x2200000 |
| gz-log / unmap2 / mkp | 0x7E800000 / 0x7EA00000 / 0x7EE00000 | 0x41000 / 0x400000 / 0x400000 |
| gz | 0x7F200000 | 0xD00000 |
| log_store | 0x7FFBF000 | 0x40000 |
| emi_mbist_buf | 0x7FFFF000 | 0x1000 |
| atf-log-reserved | 0xBFE00000 | 0x200000 |
| RKP / RKP_NS | 0xD0000000 / 0xD0200000 | 0x200000 各 |
| framebuffer | 0xFE20F000 | 0x1DF0000 |
| dramc-rk0/rk1 | 0x1BFFFE000 / 0x33FFFE000 | 0x2000 各 |
| me_cmdq_reserved | 0x33FE00000 | 0x100000 |
| SSPM | 0x7E880000 | 0x180000 |

> expdb 跨多次启动，个别项（如 `system_bl2-ext` 0x62F00000/0x2000000）
> 只出现在一次会话；做内存图前应再抓一次干净的正常启动 LK 日志核对。

### 2.2 与 pearl 的逐项对齐（最重要的可行性证据）

pearl 的 `PlatformMemoryMapLib.c` 在 `0x40000000..0x50700000` 与 iQOO 实测
**逐项同址**：kinfo 0x48080000、pstore 0x48090000、minirdump 0x48170000、
BL31 0x48200000、crypto 0x48401000、UEFI FD 0x50000000（正好止于
aee_lk 0x50700000）。因此 pearl 的低端布局可以直接复用。

高端需按 2.1 改写（差异示例）：TEE 0x6200000（pearl 0x6000000）、
tee-secmem 在 0x7BE00000（pearl 0x7C800000）、smmu protpgd 0x7C600000、
MCUPM 0x7C500000、SSPM 0x7E880000、gz 0x7F200000、log_store 0x7FFBF000。
**不能整表照搬 pearl 的高端映射。**

### 2.3 外设地址（DTS 实测）

| 外设 | 地址 | 与 pearl 对比 |
|---|---|---|
| GICD / GICR | 0x0C000000 / 0x0C040000 | 相同 |
| UFS HCI | 0x112B0000（`mediatek,mt8183-ufshci`） | 相同 |
| OVL0 / OVL0_2L | 0x14002000 / 0x14003000 | 相同 |
| DSI0 / disp_pwm | 0x14017000 / 0x1100E000 | 相同 |
| watchdog | 0x1C007000 | 相同 |
| keypad / PMIF | 0x1C00E000 / 0x1C804000 | 相同 |
| UART | 0x11002000 | 相同 |
| 定时器 | 13 MHz，PPI 29/30/27/26 | 相同 |

### 2.4 显示

- LK framebuffer：`0xFE20F000`，mblock 大小 `0x1DF0000`（约 31.3 MiB）。
- 反推：`1088 × 2388 × 4 × 3 = 31,177,728 B (≈31.18 MB)`，mblock
  `0x1DF0000 = 31,326,208 B (≈31.33 MB)`，差值来自对齐；
  iQOO Z8 面板规格为 **1080 × 2388**，pitch 1088，3 层，RGB/BGRX。
- LK fastboot 界面由 LK 点亮；pearl 的 `SimpleFbDxe` 直接改写 OVL
  layer 地址/pitch/format，指向 `0xFE20F000`。若面板为 command mode，
  还需像 degas 一样在 BLT 后触发 DSI（4 个 mutex），否则只写内存不刷新。

## 3. LK 最终启动路径（新逆向证据）

`boot_linux_fdt`（0xC0BC）在末尾（0xD09C）调用 `0x1CA10`：

```
x0 = 0xFFFF00008000D0C8   ; 位于 LK 内的 SMC 桩
x1 = 0xC2000115           ; MTK SIP: kernel boot
x2 = kernel entry (PA)
x3 = DTB (PA)
x4 = 0
bl 0x1CA10
```

`0x1CA10` 依次：

1. `bl 0x516F8`（no-op）、`bl 0x2818`（platform quiesce：停从核/外设）；
2. 用 `0x68500` 把桩 VA 和 `0x1C7C8` trampoline 转成 PA；
3. 清 SCTLR.WXN、写 `TCR_EL1=0x2_0000_B510_7516`、`0x1C96C(3)` 关 I/D cache；
4. `blr` 到 **PA 0x8001C7C8** 的 trampoline：`msr sctlr_el1` 清 M 位
   （关 MMU）→ `tlbi vmalle1` → `br x4`；
5. `x4` 指向 `0xD0C8` 桩：`mov x4,#1; smc #0`。

SMC 桩（0xD0C8）与 degas 文档完全一致：**LK 不是直接跳内核，而是把
“入口 + DTB + x4=1”通过 SMC `0xC2000115` 交给 ATF**，由 ATF 进入内核。
degas 实测 ATF 正常写 EL2h（`0x3c9`），其 GZ 再改成 EL1h（`0x3c5`）；
入口 `SCTLR_EL1.M/C=0`，`HCR_EL2.VM=1`。

**对 RAWBOOT 的意义**：无需自己切 MMU/EL。handler 只需把 payload 复制到
`0x40080000`、刷 cache，然后调用 LK 的 `0x1CA10`（或直接复刻
`quiesce + 关 cache + SMC`）即可复用这条 MTK 标准交接路径；degas/MT6897
已用同一 SMC 真机进 UEFI，pearl 源码树同路径。

## 4. pearl EDK2 本地构建与仿真结果

### 4.1 构建

- 基座：`tianocore/edk2@5801910`（`.gitmodules` 固定值）+ `edk2-platforms@d8232e8`；
  但该 edk2 缺少 DSC 需要的 `BaseVariableFlashInfoLib`，已从
  `edk2-stable202411` 补入；另补 `brotli v1.1.0`（BaseTools 与
  MdeModulePkg）和 `jansson v2.14`（RedfishPkg/JsonLib）。
- 工具链：clang/LLD 18.1.3、iasl 20230628、aarch64-linux-gnu-gcc。
- 修复：BaseTools 在 GCC 13 下加
  `-Wno-error=use-after-free -Wno-error=dangling-pointer`；pearl DSC 增加
  `*_*_*_ASLCC_FLAGS = -x c -Wno-unused-command-line-argument`（clang 18
  对 ACPI link 步尾部的 `-x c` 报错）。
- 结果：`build -p Platform/Xiaomi/pearlPkg/pearl.dsc -a AARCH64 -t CLANG38
  -b RELEASE` 成功。

```
Build/pearl/RELEASE_CLANG38/FV/PEARL_UEFI.fd
size   7,340,032 (0x700000)
sha256 6d9430272c595cc4c47417a7ed7ea948e460b03ac58887650f879b0becc36626
Sec (PrePi) TE: Base=0x50001160 Entry=0x50007560
FV ZeroVector @0x00 = b 0x7560（FD base 就是可执行入口）
```

BootShim（`UEFI_BASE=0x50000000 UEFI_SIZE=0x700000`）：

```
BootShim.bin 144 B  sha256 cdda42faed9f719dc415810cb86206011ab1298bc95345e5e9adff86828ac8f3
shim+FD     7,340,176 B sha256 7eb7ee52a174cbe5ffb2fd193281838c66252c59641229eed6e99c0147f70235
```

### 4.2 仿真（Unicorn，`scripts/sim_bootshim.py`）

把 shim+FD 放在 `0x40080000`，执行 BootShim 的复制循环：

```
copied FD to 0x50000000: head=581d001400000000
final PC=0x50007560
```

即 FD 被完整搬到 0x50000000，FD base 的 `b 0x7560` 生效并到达 PrePi 入口。
说明 `BootShim + pearl FD` 的装载语义在 iQOO 的候选地址上成立（尚未涉及
LK/ATF 与真实 MMU）。

## 5. 路线对比与决策

| 维度 | LK RAWBOOT 直接启 UEFI | Linux → UEFI 热跳（Camellia） |
|---|---|---|
| 现有入口 | iQOO 的 `fastboot boot` 已可用，handler 已进 | 需先启动 Android/initramfs，再 insmod |
| 内核依赖 | 无；ATF SMC 直接交 UEFI | 需带 `camellia_jump_to()`/jump2 的自编译内核 + 匹配 KO |
| 刷写 | 不刷（内存启动） | 需刷 boot_a/vendor_boot_a（本机 locked + AVB） |
| UEFI 存储 | pearl 有 UFS DXE，且 LK 已初始化 PHY | Camellia 基线无 UFS DXE |
| 平台先例 | degas MT6897 真机成功；pearl MT6895 同族基线可构建（WIP） | camellia MT6833 成功，但不可直接迁移 |
| 主要风险 | SMC/GZ 一次性、看门狗、内存 carveout | 内核 ABI/源码、刷写、显示 shadow |

**决策：RAWBOOT。** 热跳保留为备选，仅当 SMC 路径在 iQOO 上被证伪时再评估。

## 6. iQOO Z8 移植清单

1. **平台包**：复制 `Platform/Xiaomi/pearlPkg` → `iqooz8Pkg`，
   `Silicon/MediaTek/MT6895Pkg` → `MT6896Pkg`；MT6896 复用 MT6895
   的 GIC/定时器/UFS/OVL 基址。
2. **PCD**：
   - FD `0x50000000/0x700000`；栈 `0x40C00000/0x40000`；
     向量 `0x40C40000`；DXE heap `0x40C50000/0x7430000`（止于 kinfo 0x48080000）。
   - FB `0xFE20F000`，pitch 1088，visible 1080，height 2388，layers 3，
     pixel format RGB；OVL `0x14002000/0x14003000`。
   - UFS `0x112B0000`、GIC `0x0C000000/0x0C040000`、
     watchdog `0x1C007000`、PMIF `0x1C804000`、keypad `0x1C00E000`。
3. **MemoryMapLib**：以 2.1 表重建；低端 `0x40000000..0x50700000` 可照
   pearl；高端逐项替换；BL33 `0x80000000..0x96000000` 在 bring-up 阶段
   先整体保留，避免 UEFI 踩 LK/下载缓冲。
4. **看门狗**：保留 `WatchDogDxe` 并确认 SEC→BDS 全程喂狗；或 bring-up
   阶段直接把 `0x1C007000` 计时器关闭。任何“约 30 秒复位”先查看门狗。
5. **UFS**：先用 `MtkUfsDxe`（仅 XOUFS bit7）；若链路异常，再按 degas
   经验补 SMC `0xC2000276` device reset / refclk 复查。
6. **显示**：先用 `SimpleFbDxe` 接管 OVL；若面板是 command mode，需在
   BLT 后触发 DSI（参考 degas 的 4 mutex 写法）。
7. **RAWBOOT payload**（在现有 v2 handler 中新增分支，格式沿用 docs/09）：
   ```
   RAWBOOT! u64 load_addr=0x40080000, entry=0x40080000,
            dtb_addr=0（或 0x47C80000）, payload_size
   payload = BootShim + FD
   ```
   handler：拷贝 → `dc civac`/`ic iallu` → 调 `0x1CA10`：
   ```
   x0 = 0xFFFF00008000D0C8（LK SMC 桩 VA；0xD0C8 = mov x4,#1; smc #0）
   x1 = 0xC2000115
   x2 = entry (0x40080000)
   x3 = dtb
   x4 = 0
   ```
   `0x1CA10` 会 quiesce、关 cache、经 trampoline SMC 交 ATF；不再返回。
   **VA/PA 注意**：handler 在 LK MMU 开启下运行，`memcpy` 的源/目标是
   VA；SMC 的 x2/x3 必须是 PA。fastboot 的 `download_base=0x8064B010`
   说明 LK 至少对 BL33 区做了低地址（疑似 identity）映射；0x40080000
   是否可直接作为 VA 写，需在 Stage 0 用“写入-回读”桩确认。若不成立，
   复用 `0x13DE4`（vmm_alloc_physical）先映射 0x40080000，再向返回的 VA 拷贝。
8. **分阶段验证**：
   - Stage 0：RAWBOOT + 只写 framebuffer 标记的小桩，确认 SMC 路径、
     CurrentEL、FB 地址；
   - Stage 1：BootShim+FD，确认 UEFI 画面/Shell；
   - Stage 2：UFS/显示/触控驱动。
   每阶段先更新 `lk_sim.py`/`sim_bootshim.py` 的仿真，再考虑真机。

## 7. 风险与门槛

- **ATF SMC 一次性/门禁**：`0xC2000115` 可能只允许一次或受 GZ/MKP 约束；
  若返回/复位，需用 Stage 0 桩读取返回值并确认。
- **EL 不确定**：degas 是 GZ→EL1；iQOO 可能 EL2。pearl PrePi 对两者都有
  分支，但 EL2 下 MMU/GIC 行为需实测。
- **内存图不完整**：expdb 每次会话的 mblock 列表不完全一致，adsp/sspm/md
  等 carveout 可能缺失；先保守保留，勿让 UEFI 向未知区写。
- **VA/PA 拷贝**：RAWBOOT handler 在 LK MMU 下运行，写 0x40080000 前要先
  确认该低地址是 identity 映射（Stage 0 写入回读），否则用 vmm 映射后的
  VA 写入；SMC 的入口/DTB 参数必须是 PA。
- **锁定 + AVB**：RAWBOOT 不经过 storage loader，因此不会触发已确诊的
  `avb_slot_verify` NULL deref；但任何仍走 stock loader 的路径都会崩。
- **看门狗**：33.6 秒量级；先喂狗/关狗再谈 UEFI 稳定性。
- **回滚**：真机步骤必须保留已知良好的
  `images/lk_os3_setactive_keyswap_16MB.img` 与 BROM/FlashTool 通道。

## 8. 下一步（建议顺序）

1. 生成 `MT6896Pkg` + `iqooz8Pkg`，按 6.1/6.2 改 PCD，先做到本地
   PEARL 等价固件可构建（不刷）。
2. 在 v2 payload 中实现 RAWBOOT 分支与 `0x1CA10` 调用；用 `lk_sim.py`
   模拟“下载缓冲区 → 0x40080000 → SMC 参数”。
3. Stage 0 小桩 + expdb 回读方案（不刷 LK，先用现有 fastboot boot 通道
   下载 RAWBOOT payload）。
4. 通过后再讨论是否刷 `lk_a`/是否直接 `fastboot boot`。

## 9. 复现命令（本地）

```bash
# EDK2
cd work/refs/edk2-mt6895-pearl
make -C Common/edk2/BaseTools -j4 \
  EXTRA_OPTFLAGS='-Wno-error=use-after-free -Wno-error=dangling-pointer'
export CLANG38_BIN=/usr/lib/llvm-18/bin/ CLANG38_AARCH64_PREFIX=aarch64-linux-gnu-
export IASL_PREFIX=/usr/bin/ WORKSPACE=$PWD
export PACKAGES_PATH=$PWD/Platform/Xiaomi:$PWD/Common/edk2:$PWD/Common/edk2-platforms:$PWD/Silicon/MediaTek
source Common/edk2/edksetup.sh
build -p Platform/Xiaomi/pearlPkg/pearl.dsc -a AARCH64 -t CLANG38 -b RELEASE -j4

# BootShim + 仿真
make -C BootShim UEFI_BASE=0x50000000 UEFI_SIZE=0x700000
python3 scripts/sim_bootshim.py \
  BootShim/BootShim.bin Build/pearl/RELEASE_CLANG38/FV/PEARL_UEFI.fd
```
