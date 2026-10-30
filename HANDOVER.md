# HANDOVER — iQOO Z8 LK 成果 & UEFI/XNU 研究交接

> 写于 2026-10-30。新对话请先读本文件，再读 `STATUS.md`、`docs/07`、`docs/09`。
> 仓库根目录：`<repo>`（Windows/WSL 均可）

## 0. 2026-10-30 UEFI 最新状态（优先于下方旧章节）

- **UEFI 已启动（v5 真机确认）**。刷 `images/lk-v5.img` +
  `fastboot boot images/fastboot_boot_work/uefi.img` 成功进入 UEFI。
  - LK v5：`dist/lk.img` sha256
    `6aea4c4258ac0f639e1ec2ce103db7b54eb607435173a26fb5f803e8e20a8ddd`；
  - 镜像：`dist/uefi.img` 1,091,584 B，sha256
    `9b89578a61e7150ecbc7e84e17a66744fae7abef41294949c869cb2a262abdf6`
    （kernel_addr=0x40000000，DTB 紧接 kernel）。
- 关键链路：fastboot boot → bootimg handler → skip storage loader →
  dtbo overlay（0xc3f0 钩子，正确基址/size）→ mb_dtb → mb_kernel
  (0x7c80000 @0x40000000) → 解压 BootShim+FD 到 0x40000000 →
  io_task/set_fdt → bootconfig 跳过（0xcb7c 钩子）→ SMC 0xC2000115 →
  BootShim → UEFI PrePi（0x50000000）。
- 三个致命坑（已修）：
  1. magic 不能放 `g_boot_info+0x668`（覆盖 v2 头 `dtb_size`，
     变成 "-BOO"=0x4F4F422D，overlay 必失败）；v4 起放 `LK+0xf3100`；
  2. LK v2 的 x26 = `img+page+align(kernel)` = 实际 DTB 偏移，
     **不要加 DTB gap**；
  3. kernel_addr 必须 0x40000000（mb_kernel 固定 0x7c80000 区域）。
- 待记录：屏幕最后阶段（DEBUG/BDS/Shell）、稳定性、外设（UFS/显示/
  触控/Wi-Fi）状态。后续工作从“能启动”转向 UEFI 驱动/OS 启动。
- 发布准备：已移除本机路径/文件名；`docs/12-porting-guide.md` 给出通用
  移植方法；仓库不包含固件/签名工具。
- WSL adb 已安装（platform-tools 37.0.1），Windows adb server 以 `-a`
  监听、防火墙放行后 WSL↔host 桥接可用；但设备侧 ADB 接口枚举正常却不
  响应（`0e8d:201c`，需拔插 USB 重枚举），暂未建立可行调试通道。
- 必读：`STATUS.md` v5 段、`docs/11-rawboot-uefi-flash.md`。
  公开分支为单提交快照（初始公开版本），不包含内部开发历史。
- FlashTool 短名：`images\lk-v5.img`、`images\fastboot_boot_work\uefi.img`、
  `images\lk-recovery.img`。
- 本文 §5 的旧“UEFI 专项开场”已被本节取代。

## 1. 一句话状态

- **UEFI 已在 iQOO Z8 上通过 LK `fastboot boot` 启动**（v5）：合法 v2 bootimg
  → 跳过 storage loader/AVB → stock dtbo overlay → mb_dtb/mb_kernel →
  解压 BootShim+FD → SMC 0xC2000115 → UEFI PrePi。
- 正常 Android boot 保持原逻辑（所有钩子仅在 magic 命中时生效）。
- 设备侧 ADB 目前不稳定（接口在、协议不响应），待恢复后做 UEFI 驱动/OS
  启动的下阶段工作。
- XNU/iOS 方向仍无公开 MT6896 端口；可参考 HakiOS MT6768/MT6789。

## 2. LK 成果（当前成品）

| 项 | 值 |
|---|---|
| 产物 | `dist/iqooz8-os3-fastboot-boot-16MB.img` |
| 短名副本 | `images\fastboot_boot_work\lk_fb.img`（本地 FlashTool 目录） |
| 大小 | 16,777,216 B |
| SHA256 | `984c2f60d4b0ea02084acb56632f278fed49258fd73325fc8426e48af4a90018` |
| MD5 | `60f51835e122c1d38c39affab5de4113` |
| 输入 | 目标机 `os3-unlockless/lk.bin`（自备；sha256 034d97fa...d2d0b） |
| 证书 | CERT1/CERT2 签名外部验证 VALID（`verify_mtk_image.py`） |
| fastboot | 原 6 条命令全部保留；`boot` flags (1,0)，locked 可用 |

### LK 关键逆向结论

- LK 是 AArch64、自重定位 PIE；MKIMG 容器；lk dsize 0xcef90，BSS 0xd0000。
- fastboot 注册 `0x8120`，`fastboot_register` `0x4be8`，链表头 0xf20a8；
  handler ABI `(arg, download_base, download_size)`。
- 启动链：`load_bootinfo_from_hdr 0x9d00` → `bootinfo_set_image 0xa6ec` →
  `boot_linux_from_storage 0xd0d4` → `boot_linux_fdt 0xc0bc`。
- boot mode：**0=normal, 2=recovery**；storage loader：**mode 0=boot, mode 1=recovery**。
- 官方 fastboot 发 `FB_CMD_BOOT="boot"`；先 download 再 boot。

### v2 payload / 补丁

- payload 链接在 **0x1880**（VBAR=0x1000 向量同页的可执行零洞，0x187c..0x2400
  全零、无引用）；lk dsize 保持 0xcef90。
- 符号：stub 0x1880、wrapper 0x18a8、handler 0x18f8、boot_cmd 0x1a58、
  magic 0x1a60。
- 补丁：
  - 0x81d8 `0x17fff284` → `0x17ffe5aa`（b 0x1880）
  - 0xd12c `0x94011236` → `0x97ffd1df`（bl 0x18a8）
  - 0xd15c `0x9401122a` → `0x97ffd1d3`（bl 0x18a8）
- handler 流程：保存/强制 mode=0 → `storage_image_loader(0)` 加载 stock
  boot/vendor → `load_bootinfo(download)` 覆盖 boot 头 → `bootinfo_set_image`
  → magic → `boot_linux_from_storage`（wrapper 跳过其 loader 重载）。
- 日志：`printf 0x6b570` 输出 `kaeru-fb-boot:`，进 LK log/expdb。

### 已确诊的两次真机问题

1. **v1 NX 崩溃**（已修复）
   - payload 放 0xcef90 数据尾部；expdb：
     `instruction abort: PC at 0xffff0000800cef90` → panic/die。
   - 修复：移到 0x1880 可执行页。详见 `docs/07`。
2. **v2 进入 handler 后 AVB NULL deref**（未修复，属于 Android 启动路径设计）
   - expdb：`kaeru-fb-boot: start size=0x6000000` 之后
     `check_device_unlock_auth verify failed`、`AVB: force img_auth_required=1`、
     `boot_b: Hash of data does not match digest`、`heap_grow failed`、
     `AVB: Failed to allocate memory`、`data fault PC 0x...16dbc FAR 0x10`、
     `panic die / HALT`。
   - 原因：handler 先调 stock storage loader，在 locked 下校验存储 boot_b；
     boot_b 被改过（Magisk），96MB 镜像又把 AVB 堆撑爆；`avb_slot_verify`
     返回 NULL，LK 0x16dbc 未判空 `ldr x8,[x0,#16]`。
   - host 的 `Booting FAILED (Status read failed (Too many links))` 是设备
     panic/reboot 导致 USB 断开，不是 fastboot 不认命令。
   - 详见 `docs/09`。

### 模拟器/门禁

- `scripts/lk_sim.py`：按 LK 的 RX/RW 页权限执行成品真实字节；
  - 正向：真实 0x8120 → 0x81d8 → 0x1880，7 条注册；
  - 负向 v1：0xcef90 NX → `UC_ERR_FETCH_PROT`，PC=0xcef90，精确复现 expdb。
- `scripts/verify_output.py` / `emulate_payload.py` / `lk_flow_sim.py`；
- `make verify` 全部通过；最新 commit：`6ea4460`（AVB 记录）、`b2a62c6`
  （汇编级模拟器）、`4925012`（NX 修复）。

## 3. 设备 / 文件状态

- 设备当前应为 **v2 已刷入 lk_a**（最近 expdb 显示 v2 进 fastboot）；未由我
  刷写。最近一次 `fastboot boot` 因上述 AVB panic 重启，设备仍可回 fastboot。
- `fastboot_boot_work/expdb/expdb.img` 是最近一次完整证据。
- FlashTool `images/` 里的 `lk_os3_setactive_keyswap_16MB.img` 是已知良好的
  另一版 LK，可用于恢复；`preloader_raw_b.img`、`logo_b.bin` 不要动。
- 旧 v1/long-name 文件已清理；`lk_fb.img` 是 v2 成品。

## 4. UEFI / XNU 调研交接（2026-10-30）

### HackiOS / HakiOS（OOSEX GANG）

- `oosexgang/hakios-xnu-kernel`（1948★，注意仓库名是 **hakios** 不是 hackios）
  - XNU xnu-8796.121.2 + 未修改 iOS 16.5 user space；POCO X5 Pro 5G
    （Qualcomm SM7325）。
  - 启动方式：stock bootloader → `fastboot boot` shim → XNU；iOS root 在
    userdata；不刷 boot 分区；无 iOS 二进制。
- `oosexgang/hakios-mt6768`（4★，**公开 MTK HakiOS 端口**）
  - Infinix Hot 20 X6826B，**Helio G85 / MT6768**，eMMC、Mali-G52、4 核。
  - `mtkloader` 放在 boot_a 的 Android kernel 前面（boot v2 + chainboot.py）；
    LK 解压 kernel 到 0x40080000，mtkloader 先跑，按 pmsg 请求启动 XNU 一次，
    重启回 Android；iOS root 在 xnusys 分区。
  - 已工作：boot、CPU、eMMC 只读、display、touch、buttons、Mali/panfrost/
    Metal、SCP 加速度计部分；Wi-Fi/CONNSYS 部分；audio/camera/cellular 缺。
  - **不是 Dimensity**；fork `xillusia/hakios-mt6789` 是 MT6789 Helio G99。
- `oosexgang/hakios-uefi`（5★）
  - 基于 Project Silicium Mu-Silicium 的 UEFI；给 Qualcomm redwood 用；
    README 明确 **尚未构建/启动**，需要厂商 UEFI driver；无 MTK 平台。
- `dipa-studio/ios-sweet`（1153★）：Redmi Note 10 Pro，SM7150/SD732G；
  iOS 16.7.16 userland + XNU；`fastboot boot` shim；无 MTK。
- `MakrSas/ios-topaz`（598★）：Redmi Note 12 4G，SM6225/SD685；ios-sweet
  的移植；感谢 HackiOS；无 MTK。

### EDK2 / UEFI on MediaTek

| 仓库 | 平台 | 状态 |
|---|---|---|
| `linux-mediatek/edk2-mtk`（39★，archived） | Redmi Note 13 Pro 4G **emerald / MT6789 Helio G99**；FPlus T1100、Mashtab T1、Nokia 3.1 Plus | 可启动 mainline Linux，BSD-2；非天玑 |
| `CrackerCat/EDK2-Xiaomi-MediaTek-MT6895`（0★，branch `pearl`） | Redmi Note 12T Pro **pearl / MT6895**（天玑 8100/8200 家族） | WIP：UFS host、ACPI、ext4 read、keypad（2026-10-14/15）；无 README/release；**与你的 MT6895/6896 最接近** |
| `stanveyjiang/uefi-camellia`（1★，131MB） | Redmi Note 10 5G **camellia / MT6833 天玑 700** | **有硬件验证的 UEFI hot-jump FD + uefi_jump.ko**；release v2026.10.26；路线 LK→Linux 最小 initramfs→drm_linear→uefi_jump→UEFI；**fastboot boot 实测不可用**；cold boot 未达到同等级验证 |
| `soundrust5/Port-woa-uefi-Xiaomi-14T`（1★） | Xiaomi 14T **degas / MT6897 天玑 8300-Ultra** | UEFI + Windows 11 ARM64：8 核、显示、触控、UFS 读写已工作；GPU/WiFi/BT 未完成；公开安装未开放；有 experimental UEFI boot.img release |
| `WP4Android/edk2-mediatek`（3★） | Android MediaTek phones | WORK IN PROGRESS，几乎空仓 |

### 关键结论

1. **公开的 MTK XNU/iOS 成功案例是 MT6768（Helio G85）和 fork MT6789
   （Helio G99），不是天玑**；没有找到公开的 MT6895/6896 XNU/iOS 端口。
2. **天玑 UEFI 有公开实证**：MT6833（Camellia，热跳）、MT6895（pearl EDK2
   WIP）、MT6897（Xiaomi 14T，UEFI/WOA 实验）。
3. iQOO Z8（MT6896/D8200）最值得参考的组合：
   - **CrackerCat MT6895 EDK2**（平台/UFS/ACPI 最接近）；
   - **Camellia MT6833**（MTK UEFI 启动/热跳/framebuffer handoff 方法）；
   - **Xiaomi 14T MT6897**（现代天玑 UEFI 驱动与 Windows 侧经验）。
4. Camellia 的经验很关键：**LK 直接执行自建 BootShim/UEFI 失败**
   （约 30 秒复位），并且该机 `fastboot boot` 不可用；成功路线是
   **LK→Linux→最小 initramfs→drm_linear→uefi_jump→UEFI**。iQOO Z8 的 LK
   fastboot boot 已可用，但直接跳 UEFI 仍有 EL/MMU/ATF/显示 handoff 风险，
   需要两条路线都评估。
5. XNU/iOS：HakiOS 的 MT6768 端口可作为 **MTK 驱动/启动器参考**；MT6896
   需要新写 UFS/eMMC、显示、触控、GIC/timer、PMIC、SCP/CONNSYS 等驱动，
   工作量远大于 fastboot boot。

## 5. 新对话（UEFI 专项）建议开场

> 接手本仓库。先读 `HANDOVER.md`、`docs/09`。
> 目标：在 iQOO Z8（MT6896）上做 UEFI bring-up，优先评估
> `CrackerCat/EDK2-Xiaomi-MediaTek-MT6895` + Camellia 的 hot-jump 方法；
> 需要分析 EDK2 MT6895 平台、MT6833 热跳、MT6897 UEFI 的驱动结构，
> 决定走 LK/RAWBOOT 直接启 UEFI 还是 Linux→UEFI 热跳。
> 不要刷写；先出构建/分析/仿真结果。

### 下一步具体动作

1. 拉取/阅读 `CrackerCat/EDK2-Xiaomi-MediaTek-MT6895`（branch `pearl`）：
   `build-pearl.sh`、`Platforms`/`Silicon`、UFS/ACPI/DTB；确认是否可构建。
2. 拉取 Camellia 的 `CAMELLIA.md`/`GUIDE.zh-CN.md`/`BOOT-IMAGE.zh-CN.md`，
   复用 hot-jump FD/KO 地址约束（FD 0xA0000000，stack 0xA0200000）。
3. 拉取 Xiaomi 14T 的 `guide/English/status.md`/`installation.md` 和 UEFI
   release，分析 MT6897 的 UFS/display/touch 驱动与 boot.img 打包方式。
4. 对比 MT6896 的 LK/ATF/EL、内存映射、UFS、显示、DTB；决定
   RAWBOOT 直接 UEFI 还是 Linux 热跳。
5. 想跑 XNU/iOS 时，先以 `hakios-mt6768` 为启动器/驱动参考，再评估 MT6896
   驱动移植；不要期待现成 Dimensity XNU 端口。

## 6. 风险/注意

- 设备 locked + boot_b 被改，stock loader AVB 会 NULL deref；不要再用当前
  v2 的 `fastboot boot` 测 Android boot.img，直到改成 skip-loader/RAWBOOT
  或应用 AVB 容错。
- UEFI 直接跳转可能因 EL/MMU/ATF/显示 handoff 失败；Camellia 已证明 LK 直接
  路线在 MT6833 上失败，优先评估热跳。
- 所有操作只在自有设备；刷写/恢复自行承担风险；本仓库不执行刷写。
