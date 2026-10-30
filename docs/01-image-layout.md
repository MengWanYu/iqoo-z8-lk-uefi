# 01. 镜像与内存布局

## 1. 输入身份

| 项 | 值 |
|---|---|
| 设备 | iQOO Z8 / Y100t (PD2314, MT6895/MT6896, 天玑 8200 家族) |
| 系统 | OriginOS 3 / Android 13, `os3-unlockless` 分支 |
| 文件 | 目标机 `os3-unlockless/lk.bin`（自备） |
| 大小 | 16,777,216 B (0x1000000) |
| SHA256 | `034d97fac3162fa5f872e39f5e6bf97e9a9a47951eab654016527a4e6d5d2d0b` |
| 性质 | vivo 内部免解/免密钥 LK；AVB 已放行；CERT2 完整 |

## 2. MKIMG 容器（part_hdr 链）

MTK 分区镜像由连续的 `part_hdr_t`（0x200 字节） + 数据组成。本 LK 镜像的
`part_hdr` 关键字段：

- magic `0x58881688`；扩展 magic `0x58891689`
- `dsize`（+0x04）、name[32]（+0x08）、maddr（+0x28）、mode(+0x2c)、
  hdr_sz（+0x34）、hdr_ver（+0x38）、img_type（+0x3c）、
  img_list_end（+0x40）、align_sz（+0x44）、dsize_ext（+0x48）、maddr_extend（+0x4c）。
- 链表按顺序排列，`img_list_end=1` 结束；没有绝对文件偏移，因此插入/重签导致
  后续子分区顺移是安全的（preloader 顺序解析）。

### 输入子分区

| # | 名称 | hdr off | data off | dsize | type | end |
|---|---|---|---:|---:|---:|---:|
| 0 | lk | 0x0 | 0x200 | 0xcef90 | 0x0 | 0 |
| 1 | cert1 | 0xcf190 | 0xcf390 | 0x6c7 | 0x2000000 | 0 |
| 2 | cert2 | 0xcfa60 | 0xcfc60 | 0x419 | 0x2000002 | 0 |
| 3 | bl2_ext | 0xd0080 | 0xd0280 | 0x98998 | 0x0 | 0 |
| 4 | cert1 | 0x168c20 | 0x168e20 | 0x6c7 | 0x2000000 | 0 |
| 5 | cert2 | 0x1694f0 | 0x1696f0 | 0x3bf | 0x2000002 | 0 |
| 6 | aee | 0x169ab0 | 0x169cb0 | 0xe2360 | 0x0 | 0 |
| 7 | cert1 | 0x24c010 | 0x24c210 | 0x6c7 | 0x2000000 | 0 |
| 8 | cert2 | 0x24c8e0 | 0x24cae0 | 0x3bf | 0x2000002 | 0 |
| 9 | lk_main_dtb | 0x24cea0 | 0x24d0a0 | 0x50750 | 0x0 | 0 |
| 10 | cert1 | 0x29d7f0 | 0x29d9f0 | 0x6c7 | 0x2000000 | 0 |
| 11 | cert2 | 0x29e0c0 | 0x29e2c0 | 0x3bf | 0x2000002 | 1 |

内容实际止于 ~0x29e67e，之后到 16MiB 为 0 填充。

### 输出子分区（本文成品）

| 名称 | hdr off | dsize |
|---|---:|---:|
| lk | 0x0 | 0xcef90 |
| cert1 | 0xcf190 | 0x6c7 |
| cert2 | 0xcfa60 | 0x473 |
| bl2_ext | 0xd00e0 | 0x98998 |
| cert1/cert2 | 0x168c80 / 0x169550 | 0x6c7 / 0x3bf |
| aee | 0x169b10 | 0xe2360 |
| cert1/cert2 | 0x24c070 / 0x24c940 | 0x6c7 / 0x3bf |
| lk_main_dtb | 0x24cf00 | 0x50750 |
| cert1/cert2 | 0x29d850 / 0x29e120 | 0x6c7 / 0x3bf（end=1） |

payload 位于 lk 数据内部的可执行零洞 0x1880（lk dsize 不变）；增长仅来自
CERT2 override 块（0x419 -> 0x473），后续子分区顺移，最后仍填充到 16MiB。

## 3. 架构、自定位与入口

- lk 子镜像为 **AArch64 裸机代码**，无 ELF 头；IDA 工程约定
  `VA = 0xFFFF000080000000 + lk_data_offset`。
- **自重定位 (PIE)**：入口（data offset 0x0）首先 `bl 0x1c7a0`、`bl 0x36ac`，
  调整 `SCTLR_EL1`（I/C/A/SA），然后：
  - 清零 `BSS`：`0xd0000..0xd1000`（`0x200` 个 qword）；
  - 处理 `0xb1000` 处的 relocation 描述符表；
  - 调用后续 early init。
- 由于代码/数据引用均基于 PC 相对寻址（ADRP/ADD、ADR、B/BL），payload
  只要按 **镜像内偏移** 链接即可随 LK 一起重定位；不需要额外 relocation 项。

### 关键运行时布局（相对 LK 加载基址 `LK_base`）

| 偏移 | 内容 |
|---:|---|
| 0x0 | lk 镜像入口 / 自定位 |
| 0x81d8 | fastboot 注册函数最后一条 tail `b fastboot_register`（被改为 `b payload_stub`） |
| 0x9d00 | `load_bootinfo_from_hdr(hdr)` |
| 0xa6ec | `bootinfo_set_image(boot_img, vendor_img)` |
| 0xb1000 | relocation 描述符表 |
| 0x1880..0x1bb6 | **payload（822 B，可执行零洞；VBAR=0x1000 同页）** |
| 0xcef90 | 原 lk 数据结束（dsize 不变） |
| 0xd0000 | BSS 起始（入口清零 0x1000） |
| 0xf20a8 | fastboot 命令链表头 |
| 0xf20d0 | fastboot download_base |
| 0xf2140 | fastboot download_size（u32） |
| 0xf2828 | `g_boot_info`（boot 头镜像，拷贝 0x67c B） |
| 0xf2e90 | `g_boot_info + 0x668`：本方案 magic（代码零访问，见 04） |
| 0xf2ea8 | vendor_boot 头镜像（拷贝 0x850 B） |
| 0xf3708 | boot image base |
| 0xf3710 | vendor_boot image base |
| 0xf3718 | **boot mode 全局**（0=normal, 2=recovery） |
| 0xf3xxx | boot_info 其它标志、key 表等 |

## 4. 证书、AVB 与安全链

- 每个可加载子分区后跟 cert1/cert2；cert2 含 **image header hash** 与
  **image hash**（SHA-256）。
- 输入镜像的 4 个 CERT2 均校验通过（`verify_cert2_hashes`）。
- 修改 lk 内容后必须重签 CERT2；本仓库使用项目已有
  `tools/lk-patcher-master/mtk_img.py::sign_image_bytes`，采用
  **CVE-2023-20696 overlay**（前置 `[a0]` hash override 块，保留原证书 DER 与签名）。
  > 注：`tools/lk-patcher-master` 为外部工具，**不在本仓库**；需自行准备
  > 合法重签能力。
  仅重签 lk 的 cert2；bl2_ext/aee/lk_main_dtb 未修改，其 cert2 保持原样。
- 输出 CERT2 全链校验通过；lk cert2 由 0x419 增长到 0x473，后续子分区顺移。
- 该输入本身是 `os3-unlockless`（AVB 放行）构建；本方案不改变 AVB/seccfg
  语义，只新增 fastboot 命令与 boot-from-memory 流程。

## 5. 产物

```
dist/iqooz8-os3-fastboot-boot-16MB.img
size   16777216
sha256 984c2f60d4b0ea02084acb56632f278fed49258fd73325fc8426e48af4a90018
```

manifest 记录输入/输出哈希、payload 哈希、补丁点与最终 part 表。
