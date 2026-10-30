# 函数/全局偏移表（本 OS3 LK）

> 所有偏移均为 **lk 子分区数据偏移**（不含 0x200 part_hdr）。运行时
> `VA = LK_base + offset`，`LK_base` 由 preloader 决定；项目 IDA 约定
> `LK_base = 0xFFFF000080000000`。证据来自 objdump/capstone、项目 lk.elf/IDB
> 命名习惯以及 Unicorn 仿真。

## Fastboot

| 偏移 | 名称/作用 |
|---:|---|
| 0x4be8 | `fastboot_register(name, handler, w2, w3)` |
| 0x4bb0 | 释放命令链表 |
| 0x4c58 | 释放某类链表 |
| 0x4cac | 注册/发布辅助（name/value） |
| 0x8120 | 原 fastboot 命令注册函数（6 条） |
| 0x81d8 | 最后一条 `ultraflash:` 注册的尾调用 `b 0x4be8`（补丁点） |
| 0x81dc | `download:` handler |
| 0x8294 | `flash:` handler |
| 0x8908 | `erase:` handler |
| 0x89d4 | `oem ultraflash:` / `ultraflash:` handler |
| 0x8b78 | `oem ultraflash_en` handler |
| 0x527c | fastboot 命令循环/传输状态 |
| 0x5420 | 命令链表匹配循环 |
| 0x54c0 | flag1/flag2/lock 门 |
| 0x5508 | `blr handler` |
| 0x5279c | 设置 fastboot 状态全局 (0xb5000+0x674) |
| 0x527a8 | 根据状态输出 |
| 0xf20a8 | fastboot 命令链表头 |
| 0xf20b8 | fastboot 传输/控制器对象 |
| 0xf20d0 | download_base |
| 0xf2140 | download_size (u32) |

命令节点布局：`next@0, name@8, name_len@0x10, flag1@0x14, flag2@0x18,
handler@0x20`，大小 0x28。

## Boot / boot image

| 偏移 | 名称/作用 |
|---:|---|
| 0x9d00 | `load_bootinfo_from_hdr(hdr)`：magic ANDROID!/VNDRBOOT，拷贝 0x67c/0x850 |
| 0x9ee8 | header_version (g_boot_info+0x28) |
| 0x9f94 | kernel_addr（v0-v2:+0xc；v3/v4 归一化） |
| 0xa1f4 | kernel_size (+0x8) |
| 0xa240 | ramdisk_addr（v0-v2:+0x14；v3/v4 vendor） |
| 0xa5f4 | ramdisk_size（v0-v2:+0x10；v3/v4 + vendor） |
| 0xa68c | tags/dtb addr（v0-v2:+0x20；v3/v4 vendor） |
| 0xa0e4 | kernel 源指针 = image_base + page_size |
| 0xa2a0 | DTB 源指针 |
| 0xa35c | vendor ramdisk 源指针 |
| 0xa3f8 / 0xa484 | DTB / vendor ramdisk 大小 |
| 0xa6ec | `bootinfo_set_image(boot, vendor)` |
| 0xc0bc | `boot_linux_fdt(kernel, dtb, ramdisk, ramdisk_size)` |
| 0xc3dc..0xc3f4 | dtbo overlay 调用点：x2=dtbo、w3=dtbo_size、x0=x26(base)、w1=w27(size)、x4=&out |
| 0xc448..0xc4cc | overlay 后处理：fdt_open_into 到 vm_dtb(0x47c80000)，`free(*out)`（*out!=x26 时） |
| 0x72700 | `ufdt` overlay 包装（ufdt_install_blob 0x60bb4 + overlay 0x60c70） |
| 0x60bb4 / 0x60c70 | `ufdt_install_blob(fdt,size)` / `ufdt_overlay_apply(fdt,size,ovl,size)` |
| 0xd0d4 | `boot_linux_from_storage()` |
| 0xadd4 | bootconfig appender(fdt, dest)：把 "#BOOTCONFIG" 追加到 vendor ramdisk |
| 0xcb7c | bootconfig 调用点：dest = 0xffff000066f00000 + vendor ramdisk size |
| 0xd12c | `bl storage_image_loader(1)`（recovery 路径） |
| 0xd15c | `bl storage_image_loader(0)`（boot 路径） |
| 0xd6f8 | 计算参数并 `bl boot_linux_fdt` |
| 0xd760..0xd890 | vendor ramdisk / DTB 拷贝/解压 |
| 0xd8e4 | `mt_boot_init` |
| 0xdab4 | `mt_boot` -> 0xdac4 + 0xd0d4 |
| 0x51a04 | `storage_image_loader(mode)` |
| 0x51aac/0x51b70 | mode 0 (boot) / mode 1 (recovery) 分区列表 |
| 0x517b0 / 0x517f0 / 0x51740 | loader 辅助 |
| 0x59864 | 镜像加载/校验辅助 |
| 0x13de4 | vmm_alloc 类 |
| 0x6beec | memcpy |
| 0x6b570 | printf（stdio/log） |

## Globals

| 偏移 | 内容 |
|---:|---|
| 0xb1000 | relocation 描述符表 |
| 0x1880 | payload 注入点：可执行零洞（VBAR=0x1000 同页；0x187c..0x2400 全零） |
| 0xcef90 | 原 lk 数据结束（dsize 不变；v1 曾把 payload 放这里，NX 崩溃） |
| 0xd0000 | BSS 起始，入口清 0x1000 |
| 0xf20a8 | fastboot cmd list |
| 0xf2828 | g_boot_info（boot header 0x67c 拷贝；+0x670=dtb_size，+0x674=dtb_addr） |
| 0xf2e90 | g_boot_info+0x668：旧 magic 槽（会覆盖 dtb_size，v4 起废弃） |
| 0xf3100 | v4 magic 槽（vendor_boot header 拷贝区 +0x258；ANDROID! 路径不用） |
| 0xf2ea8 | vendor_boot header 拷贝 |
| 0xf3708 | boot image base |
| 0xf3710 | vendor_boot image base |
| 0xf3718 | boot mode（0 normal, 2 recovery） |
| 0xf3xxx | boot_info 标志/其它 |

## Boot mode / loader

- `0xa784` 读 0xf3718；`0xa790` 模式选择（写 0/2/0x63 等）。
- `storage_image_loader(0)`：列表 “boot”（0xa4f28）+ vendor_boot。
- `storage_image_loader(1)`：列表 “recovery”（0xa4f40）+ vendor_boot。
- v3/v4 启动需要 vendor_boot；boot.img 只提供 kernel。

## 本仓库 payload

| 符号 | 偏移 |
|---|---:|
| payload_base/stub | 0x1880 |
| load_wrapper | 0x18a8 |
| overlay_hook | 0x18f8 |
| memmove_up | 0x1a3c |
| bootconfig_hook | 0x1a78 |
| boot_handler | 0x1acc |
| boot_cmd | 0x1d00 |
| magic | 0x1f40 |

补丁点：0x81d8（b 0x1880）、0xd12c/0xd15c（bl 0x18a8）、
0xc3f0（bl 0x18f8，overlay 钩子）、0xcb7c（bl 0x1a78，bootconfig 钩子）。
详见 04/07/11。

v2 路径的基 DTB 指针：LK 对 0 长度的 ramdisk / recovery_dtbo 段各加 1 页，
`x26 = img + page + align(kernel) + page + page`；unpadded 镜像为
0xba800，而实际 DTB 在 0xb9800。v3f 钩子按 FDT magic + totalsize 重新定位。

注意：magic 若放在 g_boot_info+0x668 会覆盖 +0x670 dtb_size（"-BOO"
=0x4F4F422D）与 +0x674 dtb_addr，使 overlay 必然 Bad fdt size；v4 起
magic 固定为 LK+0xf3100。

## 证据/校验命令

```bash
aarch64-linux-gnu-objdump -D -b binary -m aarch64 --adjust-vma=0 lk_payload.bin ...
r2 -a arm -b 64 -m 0 lk_payload.bin
python3 scripts/lk_flow_sim.py        # 真实 LK 0x8120 注册 + 分发门模型
python3 scripts/emulate_payload.py    # stub/wrapper/handler Unicorn
python3 scripts/verify_output.py      # 容器/CERT2/补丁/差异
```
