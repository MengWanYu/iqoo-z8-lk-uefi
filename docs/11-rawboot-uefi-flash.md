# 11. iQOO Z8 UEFI 首启：v5（magic 迁址 + overlay/bootconfig 钩子）

> 2026-10-30。目标：UEFI 自己跑起来并在屏幕输出 DEBUG 日志；不要求启动
> Android/iOS。本仓库只生成文件，刷写由用户执行。
>
> **当前状态：UEFI 已启动（v5 真机确认）。**
> v4 打通 overlay/DTB/mb_kernel/解压/set_fdt；v5 跳过 bootconfig 后
> 成功进入 BootShim → UEFI PrePi。

## 0. 根因（2026-10-30 最终定位）

v2/v3f payload 把 fastboot-boot magic 写在 `g_boot_info+0x668`。该 16 字节
正好覆盖 v2 boot header 的尾部字段：

```
g_boot_info+0x668  "KAER"   recovery_dtbo_offset 高 4 字节
g_boot_info+0x66c  "U-FB"   header_size        <- 被覆盖
g_boot_info+0x670  "-BOO"   dtb_size           <- 被覆盖成 0x4F4F422D
g_boot_info+0x674  "T!!!"   dtb_addr 低 4 字节
```

`boot_linux_fdt` 的 v2 路径用 `dtb_size` 作为 overlay 的基 DTB 尺寸。因此：

- 任何 DTB 内容 / 任何基址都会 `ufdt_apply_overlay(): Bad fdt size!`；
- v3f 钩子按 `totalsize == w27` 扫描也必然失败（w27 被污染）；
- v4 真机实测 x26 = `download+0xb9800`（kernel 后紧接 DTB），不是
  0xba800；之前的“LK 多加了 2 页”推断是错的。
- v4 真机第二个阻塞：`boot_linux_fdt` 末尾把 bootconfig 追加到
  `0x66f00000 + vendor ramdisk size`，该区只有 storage loader 会映射
  → `data fault FAR 0xffff000066f00000`。v5 以 magic 门控跳过。

v3f expdb 另外暴露了第二个问题：`mb_kernel` 固定申请 **0x7c80000 @
kernel_addr**。镜像里 `kernel_addr=0x40080000` 与 mblock 空闲区起点
0x40000000 不一致，于是：

```
mblock_alloc ... sz: 0x7c80000 name:mb_kernel ... expect_addr:0x40080000
error cannot find a target
boot_linux_fdt:622: kernel_addr (0x0x40080000) is not taken from mb (0x0)
```

## 1. 当前成品（短名）

| 用途 | 文件 | 大小 | SHA256 |
|---|---|---:|---|
| 刷 `lk_a`（v5，待刷） | `lk-v5.img` | 16,777,216 | `6aea4c4258ac0f639e1ec2ce103db7b54eb607435173a26fb5f803e8e20a8ddd` |
| `fastboot boot` 的 UEFI 镜像 | `fastboot_boot_work\uefi.img` | 1,091,584 | `9b89578a61e7150ecbc7e84e17a66744fae7abef41294949c869cb2a262abdf6` |
| UEFI 固件本体（在 uefi.img 内） | `uefi.fd` | 7,340,032 | `7f6ca27d59e4bac7040b6ce05f34c14779d9209e22263fed313416fe29b40adc` |
| 恢复 LK | `lk-recovery.img` | 16,777,216 | `cbb2b80f6595c6f1761b3d93946c83aaee1f2a891228622ab724e30ebf9df7d8` |

## 2. v5 怎么走

lk v5 的 payload（0x1880，1744 B）：

- magic 移到 **LK+0xf3100**（vendor_boot header 拷贝区 +0x258）。我们的
  `ANDROID!` 镜像不会写这块，`g_boot_info` 的 `dtb_size/dtb_addr` 保持
  原值；正常 boot 不写 magic，仅比较，不受影响。
- `0xc3f0` 的 overlay 调用改为 `overlay_hook`：
  1. magic 未命中：原参数尾调用 stock `0x72700`，正常 boot 不变；
  2. magic 命中：从 x26 向前 0x4000 按 FDT magic + `totalsize==w27`
     找基 DTB（本镜像为 x26 或 x26-0x1000）；
  3. 找到则用该基址走 stock overlay（正常 boot 同一条 ufdt 路径）；
  4. overlay 失败则跳过，把 FDT 拷到 LK 原 x26 槽位（`*out=x26`），
     避免下游 `free()` 非堆指针，并返回 0 继续；
  5. 找不到也跳过并继续。
- 日志新增 base/size：`overlay base=0x… size=0x…`；
  失败时 `no fdt for overlay (base=… size=…)`。
- `0xcb7c`（`bl 0xadd4`）改为 `bootconfig_hook`：magic 命中时跳过
  bootconfig 追加（返回 0 字节），避免访问未映射的 vendor ramdisk
  0x66f00000；正常 boot 原样尾调用。

`uefi.img`（v5 配套）：

```
ANDROID! header v2, page 2048
kernel_addr = 0x40000000     # 与 mb_kernel/mblock 起点一致
kernel      = gzip(BootShim + UEFI FD)   # 756,272 B
dtb         = stock vendor_boot FDT      # 0x50d3c B
dtb_addr    = 0x47c80000
dtb gap     = 0              # 真机 x26 = img+page+align(kernel) = DTB
name        = "RAWBOOT-UEFI"
```

流程：handler 写 magic → `boot_linux_from_storage` 跳过 storage loader →
`boot_linux_fdt` 解析 v2 头 → stock dtbo overlay（钩子）→ FDT 拷到
`mb_dtb(0x47c80000)` → `mb_kernel` 申请 0x7c80000 @0x40000000 成功 →
解压 BootShim+FD 到 0x40000000 → `SMC 0xC2000115`（entry=0x40000000,
dtb=0x47c80000）→ BootShim 搬 FD 到 0x50000000 → UEFI PrePi。

## 3. 刷写 / 启动

1. 刷 `images\lk-v5.img` 到 `lk_a`（只写 lk_a）。
2. 进 fastboot：
   ```bash
   fastboot boot <FlashTool>\images\fastboot_boot_work\uefi.img
   ```
   `uefi.img` 是合法 v2 boot image，host **不应**打印 `creating boot image...`。
3. 预期日志：
   `kaeru-rawboot: overlay base=0x… size=0x50d3c` →
   `after overlay, fdt size(558491)` → `DT overlay ok` →
   mb_kernel 分配/解压 → io_task/set_fdt →
   `kaeru-rawboot: bootconfig skipped` → SMC → UEFI。
4. **host 端 `fastboot boot` 会一直停在 `Booting`、不返回 OKAY**：LK 成功
   交棒后不会再回 fastboot 发响应；若 UEFI 保持 USB（本次出现 ADB 端口），
   host 等不到断开也不会报错。直接 Ctrl+C 即可，设备已经在 UEFI 中；
   这不是失败。
4. 回滚：长按重启；异常时刷 `lk-recovery.img`。

## 4. 失败时看什么

| 现象 | 可能原因 | 下一步 |
|---|---|---|
| `no fdt for overlay (base=… size=…)` | 打印的 size 不是 0x50d3c → magic 又覆盖了头部；或镜像布局变化 | 核对 LK 版本/magic 地址与镜像 |
| `overlay failed, skipped` | libufdt 合并失败（堆/DTB 不匹配） | 流程应继续到 SMC；看后续日志 |
| `DT overlay ok` 后 `mb_kernel` 仍失败 | kernel_addr 不是 0x40000000 | 重新生成镜像 |
| `after overlay` 后复位 | SMC/ATF/BootShim/看门狗 | 看 panic PC、30s 定时、屏幕内容 |
| host 停在 `Booting` 不返回 | LK 已交棒、UEFI 保持 USB | 正常；Ctrl+C，设备已在 UEFI |
| 完全没 `kaeru-rawboot` | LK 不是 v5 或 boot 未进 handler | 重刷、核对哈希 |
| 约 30 秒复位 | 看门狗/ATF | 记录时间点与屏幕最后内容 |

## 4.5 UFS / Shell 变体（2026-10-31）

| 文件 | 大小 | SHA256 |
|---|---:|---|
| `uefi-ufs.img` | 1,124,352 | `cd850090765266b388d88984e13366e07107f2cb97f7a87bd3c77e25842bc528` |

- 在 `iqooz8.fdf` 恢复 `MtkUfsDxe`、`UfsPassThruDxe`、`ScsiBusDxe`、
  `ScsiDiskDxe`、`Ext4Dxe`（`iqooz8.dsc` 增加 Ext4 组件）。
- FD 仍为 7 MiB；`FVMAIN` 已 99% 满（仅 48 B 空闲），再加驱动需要把
  `FD_SIZE` 提到 8 MiB 并同步重编 BootShim。
- 测试：`fastboot boot ...\uefi-ufs.img`（LK v5 不变）。UEFI Shell 中：
  ```
  map -r
  fs0:
  ls
  ```
  能列出 UFS 分区/文件即成功。若卡住，屏幕最后一行会停在 UFS 初始化日志。
- 该镜像不改 LK，也不影响原 `uefi.img`（已知可启动版本）。

## 5. 已知限制

- 首版 UEFI 剔除 UFS/SCSI/ext4，目标是屏幕日志+BDS/Shell；UFS 后续加回。
- DEBUG DXE 日志走 FrameBufferSerialPortLib；PrePi 最早几条仍走 UART。
- 显示假设 video mode（DTS `dsi_te` disabled）；若 command mode 需后续加
  DSI trigger。
- 不刷 boot/vendor；UEFI 只从 RAM 启动。
- magic 放在 vendor_boot header 拷贝区，仅适用于 `ANDROID!` 镜像路径；
  若以后改成 `VNDRBOOT` 镜像，需要再选一个独立 BSS 槽位。
- UEFI 侧目前没有可用的 USB/ADB。启动后看到的 `0e8d:201c`
  （Windows 显示为 Android ADB Interface）是 LK 遗留的 fastboot 接口，
  不是 UEFI 的 adb；`adb devices`/`fastboot devices` 都不会响应。
  UEFI 没有初始化 USB 控制器，拔插线后端口即消失，需重启回 fastboot。
  要做 UEFI 调试通道，需要另移植 UDC/USB 栈 + adb 或 fastboot gadget。

## 6. 复现

```bash
# LK v5（payload + 5 条补丁 + CERT2 重签）
make payload image verify

# 配套 uefi.img（kernel_addr=0x40000000，DTB 紧接 kernel）
python3 scripts/make_bootimg_v2.py \
  work/refs/edk2-mt6895-pearl/BootShim/BootShim.bin \
  dist/uefi.fd work/refs/stock_vendor_dtb.bin dist/uefi.img

# overlay 钩子仿真（真实 LK 调用点 + 真实镜像）
python3 scripts/emulate_overlay.py

# 只生成文件，不刷写
```
