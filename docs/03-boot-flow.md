# 03. LK 启动流程与 `fastboot boot` 接入点

## 1. 正常启动主链

```
Preloader -> bl2_ext (EL3) -> ATF/TEE/GZ -> LK (EL1, AArch64)
    LK lk_main / bootstrap2 -> platform_init -> mt_boot_init
        -> mt_boot -> boot_linux_from_storage (0xd0d4)
            -> storage image loader (0x51a04)
            -> ramdisk/DTB copy/decompress (0xd760..)
            -> boot_linux_fdt (0xc0bc) -> jump to kernel
```

`fastboot` app 与 `mt_boot` 是同一 LK 的不同 app；进入 fastboot 后正常启动链
尚未运行。`fastboot boot` 需要在 fastboot app 内临时复用上述启动链。

## 2. 关键函数

| 偏移 | 函数 | 作用 |
|---:|---|---|
| 0x9d00 | `load_bootinfo_from_hdr(hdr)` | 识别 `ANDROID!`/`VNDRBOOT`，拷贝头到 g_boot_info / vendor 区，设置 hdr_loaded |
| 0xa6ec | `bootinfo_set_image(boot, vendor)` | 设置 img_loaded、0xf3708 boot base；header_version>=3 且 vendor 非空时设置 0xf3710 |
| 0x9ee8 | `get_header_version()` | g_boot_info+0x28 |
| 0x9f94 | `get_kernel_addr()` | v0-v2: 头 +0xc；v3/v4: vendor 归一化字段 |
| 0xa1f4 | `get_kernel_size()` | 头 +0x8 |
| 0xa240 | `get_ramdisk_addr()` | 头 +0x14（v4 走 vendor） |
| 0xa5f4 | `get_ramdisk_size()` | 头 +0x10（v4 加 vendor ramdisk） |
| 0xa68c | `get_tags/dtb_addr()` | 头 +0x20（v4 走 vendor） |
| 0xa2a0 / 0xa3f8 | DTB 源指针 / 大小 | 正常路径用于拷贝 appended/vendor DTB |
| 0xa35c / 0xa484 | vendor ramdisk 源指针 / 大小 | v3/v4 拷贝用 |
| 0xa0e4 | kernel 源指针 | image base + page_size |
| 0xc0bc | `boot_linux_fdt(kernel, dtb, ramdisk, ramdisk_size)` | 最终解压/跳内核 |
| 0x51a04 | `storage_image_loader(mode)` | 从分区加载 boot/vendor_boot，解析头，设置 g_boot_info/镜像基址 |
| 0xd0d4 | `boot_linux_from_storage()` | 正常启动主流程（含 ramdisk/DTB 拷贝） |

### storage loader 的 mode

- **mode 0 = boot**：分区列表首项为 `"boot"`（0xa4f28），并追加 vendor_boot；正常启动使用。
- **mode 1 = recovery**：分区列表首项为 `"recovery"`（0xa4f40）。
- `boot_linux_from_storage` 在 **boot mode==2（recovery）** 且 w22==0 时调用
  loader(1)，否则调用 loader(0)。

### boot mode 全局 0xf3718

- 0xa784 读取；0xa790 是模式选择/设置函数。
- 值语义与 kaeru `bootmode_t` / 本项目笔记一致：**0=normal, 2=recovery**；
  fastboot 等为其它值（如 0x63/4）。
- 本方案调用启动链前强制为 **0 (normal)**，失败恢复原值。

## 3. 正常启动流程（storage）

1. `load_bootinfo_from_hdr` 解析 storage boot/vendor 头，填充：
   - `g_boot_info` @0xf2828（boot 头，0x67c B 拷贝）；
   - vendor 头区 @0xf2ea8（0x850 B 拷贝）。
2. `bootinfo_set_image` 设置镜像基址：0xf3708（boot），0xf3710（vendor，v3/v4）。
3. 计算 kernel/dtb/ramdisk 地址与大小（helpers）。
4. 若 ramdisk_size != 0：分配/映射 2MiB 对齐目标，拷贝或解压 vendor ramdisk 与
   DTB（0xd760..0xd890），然后回到 0xd6f8。
5. 调用 `boot_linux_fdt`（0xc0bc）：
   - 检查 kernel 地址对齐、扫描 appended DTB、必要时解压 kernel、建立启动参数；
   - 跳转内核，不再返回。

## 4. `fastboot boot` 的复用方式

直接重写第 4/5 步（vendor ramdisk/DTB 拷贝、cmdline、AVB 等）风险高。方案是
**复用原 `boot_linux_from_storage`**，只替换 boot 镜像来源：

```
fastboot boot handler:
  save old boot mode; set mode=0 (normal)
  storage_loader(0)                 ; 真实加载 stock boot/vendor, 建立 cmdline/AVB 等状态
  load_bootinfo_from_hdr(download)  ; 用下载的 boot.img 覆盖 boot 头
  vendor_base = [0xf3710]
  bootinfo_set_image(download, vendor_base)  ; boot base=下载缓冲, vendor 保持
  force mode=0
  magic = "KAERU-FB-BOOT!!!" -> g_boot_info+0x668
  boot_linux_from_storage()         ; 原流程；其内部 loader 调用被 wrapper 跳过
```

原 `boot_linux_from_storage` 在 0xd12c / 0xd15c 调用 `storage_image_loader`。
这两条 `bl` 被改为 `bl load_wrapper`：

- **magic 未设置**（正常启动）：wrapper 尾调用原 0x51a04，行为不变；
- **magic 设置**（fastboot boot）：wrapper 返回 0，跳过从存储重新加载，
  使原流程使用已设置的 g_boot_info/镜像基址，继续执行 ramdisk/DTB 拷贝与
  `boot_linux_fdt`。

magic 放在 `g_boot_info+0x668`（0xf2e90）。静态扫描 0xf2e80..0xf2ea8 无任何
访问；正常 boot 头在该处几乎不可能匹配 128-bit magic。

## 5. v0-v2 与 v3/v4 行为

| 镜像 | 提供者 | 本方案 |
|---|---|---|
| v0-v2 boot.img | kernel + ramdisk/DTB 都在 boot.img | 覆盖 boot 头/基址，原流程拷贝 DTB、boot_linux_fdt 处理 kernel/ramdisk |
| v3/v4 boot.img | kernel 在 boot.img，ramdisk/DTB/cmdline 在 vendor_boot | 先 loader(0) 加载 stock vendor；覆盖 boot；原流程拷贝 vendor ramdisk/DTB；boot_linux_fdt 使用新 kernel |
| v3/v4 且 vendor 加载失败 | — | 无法完成 boot；handler 返回 fastboot，日志记录 loader ret |

Android 13 MT6895 通常为 boot v4 + vendor_boot v4；`fastboot boot boot.img`
应使用设备现有 vendor_boot（因此需要 stock vendor 分区可被 LK 读取/验证；
输入 LK 已 AVB 放行）。

## 6. 日志与 expdb

handler 的 `printf`（0x6b570）输出会进入 LK log buffer；LK 异常/重启后由
expdb 保存。关键行：

```
kaeru-fb-boot: start size=...
kaeru-fb-boot: storage loader ret=...
kaeru-fb-boot: hdr=... kaddr=... raddr=... rsize=... dtb=...
kaeru-fb-boot: magic set, entering normal boot flow
kaeru-fb-boot: calling boot_linux_from_storage
kaeru-fb-boot: skip storage reload (magic)     # 正常流程两次 loader 调用各一次
kaeru-fb-boot: failed (code), back to fastboot
```

如果 boot 成功，内核接管；如果失败/崩溃，expdb 应保留上述日志，便于判断是
loader 失败、vendor 缺失、还是 boot_linux_fdt 阶段失败。
