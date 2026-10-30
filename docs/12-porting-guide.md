# 12. 移植指南：给 MTK LK 加 `fastboot boot` 临时启动 + UEFI 引导

> 面向其他机型/其他 LK 的通用方法。文中偏移是 iQOO Z8 (MT6896, OS3 LK)
> 的实例，**不能直接照抄到别的 LK**；方法、坑位和验证手段可以复用。
>
> 仅用于自有/已授权设备。不要分发厂商固件、签名密钥或签名工具。

## 0. 前提与输入

你需要自备：

- 目标机的 `lk.bin`（本仓库不包含）；
- 目标机的 `boot` / `vendor_boot` / `dtbo` dump（用于取 stock DTB/overlay）；
- 一个可用的 CERT2 重签能力（本仓库使用外部工具，不包含私钥/工具）；
- UEFI 固件（本仓库以 pearl MT6895 EDK2 为基础改的 FD）与 BootShim；
- 可回滚的刷写/恢复通道（BROM/FlashTool 或已知良好 LK）。

## 1. 侦察 LK

1. **容器**：MTK MKIMG 多子分区（`lk/cert1/cert2/bl2_ext/.../lk_main_dtb`）。
   `lk` 子镜像的 `dsize` 是注入边界，不要越过 BSS。
2. **可执行洞**：找一段“代码/数据都零引用、且与可执行页同页”的零洞
   （本项目在 VBAR=0x1000 同页的 0x1880）。**不要放数据尾部**：LK 把数据
   页映射为 NX，取指会 instruction abort。
3. **fastboot**：找命令注册函数与最后一条注册的尾调用；把尾调用改成
   `b payload_stub`，在 stub 里补回原注册并注册 `boot`。
   handler ABI 通常是 `(arg, download_base, download_size)`。
4. **boot 路径**：`load_bootinfo_from_hdr` → `bootinfo_set_image` →
   `boot_linux_from_storage` → `boot_linux_fdt` → `SMC 0xC2000115`。
   找到 `storage_image_loader` 的两个调用点（boot/recovery），改成 wrapper。

## 2. payload 设计原则

- 位置无关（只用 `adr`/相对跳转），链接在 LK 的镜像偏移空间；
- 所有改动 **magic 门控**：magic 未命中时用原参数尾调用原函数，正常 boot
  逐字节不变；
- 只用魔法地址保存跨调用状态，**不要放进 `g_boot_info`**（见 §6）；
- 给每次 hook 输出日志前缀（如 `kaeru-rawboot:`），经 LK printf 进 expdb。

## 3. 临时启动：合法 v2 boot image

最稳的路线是复用 LK 自己的 v2 bootimg 路径（而不是直接跳 BL33）：

```
ANDROID! v2, page_size=2048
kernel      = gzip(BootShim + UEFI FD)
kernel_addr = <LK mb_kernel 期望地址>
ramdisk_addr= 非 0（满足 LK 的 ramdisk_target_addr 断言）
dtb         = stock vendor DTB
dtb_addr    = 0x47c80000（示例）
name        = "RAWBOOT-UEFI"（handler 标记）
```

关键点：

1. **kernel_addr 必须等于 LK 的 mb_kernel 固定区域起点**。本项目 LK 在
   `boot_linux_fdt` 里固定申请 `0x7c80000 @ kernel_addr`；镜像写
   0x40080000 会导致 `mblock_alloc ... cannot find a target`，随后
   `mt_boot.c:622` 断言。正确值是 0x40000000。
2. **DTB 位置**：v2 路径的基 DTB 指针
   `x26 = img + page + align(kernel)`（本机实测；0 长度 ramdisk/dtbo 段
   不额外加页）。**DTB 紧接 kernel，不要多补 0x1000 gap**；否则 x26 指向
   零区，overlay 被跳过。
3. **overlay size**：stock overlay 会检查 `[x26+4] == header.dtb_size`。
   两者必须一致；`dtb_size` 字段被 magic 覆盖是本站最大的坑（见 §6）。
4. **跳过 storage loader**：在 `storage_image_loader` 的两个调用点加
   wrapper；magic 命中直接返回 0，避免 AVB/分区校验与未映射访问。

## 4. UEFI 交棒

- 复用 LK 自己的最终跳转（`0x1CA10` 类函数）：quiesce、关 cache、VA→PA、
  trampoline、`SMC 0xC2000115`；参数一般是
  `x0=SMC stub VA, x1=SIP, x2=entry, x3=DTB, x4=0`。
- BootShim 必须是位置无关的假 Linux 头 + 拷贝器：把 EDK2 FD 搬到
  `UEFI_BASE`（本项目 0x50000000），跳到 FV 入口。
- 注意：直接 BL33 入口在部分 MTK 平台会被 ATF/GZ 拒绝（本项目已证伪），
  走 LK 的 SMC 路径更可靠。
- 看门狗：PrePi 早期关狗；如果约 30s 复位，先查 watchdog。

## 5. 需要额外 hook 的两个调用点

1. **dtbo overlay**（可选）：如果基址/尺寸不可靠，把 overlay 调用改成
   magic 门控钩子：向前扫描 FDT magic + `totalsize == w1`，用正确基址
   调用 stock wrapper；失败则跳过并把 FDT 拷回 LK 原槽位（避免下游
   `free()` 非堆指针）。
2. **bootconfig 追加**：`boot_linux_fdt` 末尾会把 bootconfig 追加到
   `vendor_ramdisk_base + vendor_ramdisk_size`。fastboot 路径没有加载
   vendor ramdisk，该区未映射 → data fault。magic 命中时返回 0（追加 0
   字节），正常 boot 原样透传。

## 6. 最大的三个坑（本机真机踩过）

| 坑 | 现象 | 修复 |
|---|---|---|
| magic 放 `g_boot_info+0x668` | overlay 永远 `Bad fdt size`；size 变成 `"-BOO"`=0x4F4F422D | 换到未被该路径使用的 BSS（本项目 `LK+0xf3100`，vendor header 拷贝区；ANDROID! 路径不写它）。改前用反汇编确认无引用 |
| 给 DTB 补 0x1000 gap | x26 指到零区，`no fdt for overlay` | 不补 gap；DTB 紧接 kernel |
| kernel_addr 0x40080000 | mb_kernel 分配失败，`mt_boot.c:622` | 用 LK 期望的 0x40000000 |

其它坑：

- payload 放数据尾部 → NX 取指；
- ramdisk_addr=0 → `ramdisk_target_addr != 0` 断言；
- storage loader 在 locked + 改过分区时会 AVB NULL deref → 必须跳过；
- host `fastboot boot` 在成功交棒后可能永远停在 `Booting`（LK 不回协议
  响应；UEFI 若保持 USB，host 也等不到断开）。Ctrl+C 即可，不是失败。

## 7. 验证手段（不刷写也能排掉大部分问题）

- **Unicorn 汇编级仿真**：按 LK 的 RX/RW 权限执行成品真实字节；负向用例
  复现 NX fault；真实调用点 + payload 钩子做参数/返回值断言；
- **离线 overlay**：`fdtoverlay` 合并 stock DTB + stock dtbo，确认可行；
- **CERT2/part 链校验**：确认重签后全链通过、未改子分区逐字节一致；
- **expdb 真机日志**：`kaeru-rawboot:` 前缀 + LK 原生日志（overlay size、
  mb_kernel、decompress、SMC）。

## 8. 迁移清单

- [ ] 找到 fastboot 注册尾调用与 boot 路径偏移
- [ ] 找到可执行零洞并确认 dsize/BSS 边界
- [ ] 确定 magic 槽位（反汇编确认无引用，且不在 g_boot_info）
- [ ] 构造 v2 bootimg：kernel_addr / ramdisk_addr / DTB 位置 / dtb_size
- [ ] 跳过 storage loader（boot/recovery 两个调用点）
- [ ] （可选）overlay 钩子；bootconfig 钩子
- [ ] BootShim + FD，SMC 参数与入口地址
- [ ] 仿真 + CERT2 重签 + 未变子分区校验
- [ ] 真机：先只刷 lk_a，保留 recovery；记录 expdb

## 9. 不要发布的内容

- 厂商 `lk.bin`、UEFI FD、boot/vendor_boot/dtbo 镜像；
- CERT 私钥、签名工具或可用的签名服务；
- 设备序列号、IMEI/rid、用户路径等个人信息；
- 未授权设备的刷写/解锁教程。
