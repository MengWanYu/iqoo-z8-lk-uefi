# 06. LK 运行全景（补充）

本文件汇总与本任务相关的 LK 运行时组成；不等于逐函数完整审计，但覆盖
fastboot/boot/security/storage/log 的主要链路。

## 1. 引导链

从 Preloader 字符串与 LK 容器可见：

```
BootROM -> Preloader (EL3) -> bl2_ext (EL3) -> ATF/BL31 + TEE + GenieZone
        -> LK/AEE (EL1, AArch64) -> Linux kernel
```

- Preloader 内有 `BL2_EXT`、`[SEC] cert verify`、`sbc_en`、`daa_en`、`sla_en`、
  `[EFUSE]` 等字符串；SBC/DAA/SLA 由 efuse 策略控制。
- Preloader 加载 `bl2_ext`、ATF/TEE/GZ，并把 LK 交给后续阶段；LK 容器里
  `bl2_ext / aee / lk_main_dtb` 与 `lk` 并列。
- LK 的 `aee` 是 MTK 异常/调试引擎；`lk_main_dtb` 是 LK 自己的 FDT
  （model=MT6895，compatible=mediatek,MT6895）。
- 本输入 LK 为 `os3-unlockless`（AVB 放行）构建；其 CERT2 完整，SBC 策略
  由设备 efuse/preloader 决定。

## 2. A/B 槽与 boot_control

- LK 内有 `[LK_AB]`、`boot_control`、`slot-unbootable:a/b`、`bootctrl_init`、
  `bootctrl_shutdown_callback` 等；A/B 元数据在 misc 分区。
- fastboot `set_active:` 注册在命令表中，handler 校验 `a`/`b` 后写
  boot_control；分发层对 `flag2=1` 命令有锁态门（本 LK 中 set_active 可能
  需要在解锁态或打补丁；项目已有 set_active 研究）。
- `boot_linux_from_storage` 通过 slot/分区名选择 boot 镜像；storage loader
  使用 `boot`/`vendor_boot` 列表。

## 3. AVB / verified boot

- 字符串/路径：`app/mt_boot/avb/load_vfy_boot.c`、`avb_allow_error`、
  `androidboot.verifiedbootstate=green/yellow/orange/red`、`vbmeta`、
  `dm-verity`、`androidboot.vbmeta.*`。
- 正常路径会读取 vbmeta、计算 hash/验证，并把 `verifiedbootstate` 写入
  cmdline；`load_vfy_boot` 可能因验证失败返回 NULL slot_data 导致 NULL
  deref（项目 `--unlockless` 的 `avb_allow_error` 补丁即为此）。
- 本输入已经过 AVB 放行处理；`fastboot boot` 复用正常启动路径时，AVB 分支
  按该输入的策略执行。若目标 boot.img 的 vbmeta 与设备不匹配，可能需要
  输入 LK 的 AVB 容错能力（输入已具备）。
- 修改 LK 内容只影响 CERT2（preloader 校验），不改变 LK 内 AVB 逻辑。

## 4. 解锁 / seccfg

- 字符串/全局：`seccfg`、`Custom get/set lock state`、`g_verify_lock_state`、
  `fb_get_verify_unlock_state`、`fb_do_verify`、`save_unlock_auth`、
  `clear_unlock_auth`、`unlock failed`、`hedgehog` key 表。
- vivo 自定义锁态：1=locked，3=unlocked；`unlock2` token 由 hedgehog 私钥
  签名，LK 用内置公钥验证后写 seccfg。
- fastboot 分发门使用 `flag1/flag2` 与锁态；`download`/`boot` 为 (1,0)，
  locked 可用；`flash`/`erase` 为 (1,1)，locked 拒绝（除非项目补丁放开）。
- 本方案注册 `boot` 为 (1,0)，不要求解锁，适合锁态 fastboot 调试。

## 5. 存储与分区

- LK 内有 UFS/eMMC、GPT/PMT、`partition_read`/`partition_get_size_by_name`、
  `mt_part`、`blkdev`、mblock 等。
- `storage_image_loader` 通过分区表读取 boot/vendor_boot；`boot_linux_from_storage`
  用 mblock/vmm 映射目标内存，拷贝/解压 ramdisk 与 DTB。
- `lk_main_dtb` 提供 LK 的设备树；`preloader` 的 mblock 布局决定 LK/boot
  image 缓冲地址。
- 本方案不写任何分区；`fastboot boot` 只把下载缓冲当作 boot image base。

## 6. fastboot / USB

- 命令注册/分发见 `docs/02-fastboot.md`。
- USB 控制器注册：`usb_register_fastboot_controller_interface`；fastboot
  状态机/空闲定时器/命令缓冲在 LK fastboot app。
- 主机端 `fastboot-rs` 先 `download:` 再 `boot`；本方案已匹配该序列。

## 7. 日志与 expdb

- LK 有 `log_store`/`log_store_lk_init`/`log_store_sync_sram`/`log_store_buf_map`
  以及 `log_store` 分区写入；`printf`（0x6b570）是 LK 日志的统一入口。
- 本项目所有 LK 日志都使用该 printf 路径；`kaeru-fb-boot:` 行会进入 LK log
  buffer，异常/重启后由 expdb 保存。可用 `fastboot oem dump_pllk_log` 或
  expdb 转储查看。
- 若目标设备的 expdb 策略未保存 LK log，可临时接 UART（若测试点可用）。

## 8. 与本任务相关的关键结论

1. LK 是 AArch64、自定位、MKIMG 容器；新增 payload 必须处理容器 dsize、
   CERT2、BSS 边界。
2. fastboot `boot` 命令缺失是**命令注册层**问题，不是启动链问题；启动链
   `load_bootinfo_from_hdr -> bootinfo_set_image -> boot_linux_from_storage ->
   boot_linux_fdt` 完整存在。
3. boot mode 0=normal、2=recovery；storage loader mode 0=boot、1=recovery。
4. v3/v4 boot.img 需要 vendor_boot 提供 ramdisk/DTB/cmdline；本方案先让
   stock loader 加载 vendor，再覆盖 boot。
5. 锁态 fastboot 下 `boot` 用 flags (1,0) 可直达 handler，无需解锁/刷写。
