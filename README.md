# iQOO Z8 (MT6895/MT6896) LK Research & `fastboot boot` Support

独立研究仓库，对象是 iQOO Z8 / Y100t (PD2314, MT6895/MT6896, Dimensity 8200
家族) OriginOS 3 (Android 13) 的 LK。

> **仓库不包含任何厂商固件、签名密钥或签名工具。** 复现需要自备目标机
> `lk.bin`（本项目输入参考 SHA256
> `034d97fac3162fa5f872e39f5e6bf97e9a9a47951eab654016527a4e6d5d2d0b`，
> 16 MiB）以及对应的 CERT2 重签能力。仅用于自有/已授权设备的研究。

## 目标

1. 逆向并规范化记录该 LK 的容器、重定位、启动链、fastboot 命令分发与启动镜像路径。
2. 在不影响原 LK 正常启动/原有 fastboot 命令的前提下，增加 `fastboot boot` 支持。
3. 通过 `fastboot boot` 临时启动 UEFI（BootShim → EDK2 FD）。
4. 输出可直接刷入 `lk_a` 的 16MB 成品镜像（本仓库不执行刷写）。

## 移植 TL;DR（给其他机型）

长文版（含原理与流程图）：**[docs/13-longread-fastboot-boot-uefi.md](docs/13-longread-fastboot-boot-uefi.md)**。
清单版：**[docs/12-porting-guide.md](docs/12-porting-guide.md)**。核心五步：

1. 在 LK 可执行零洞里注入 PIE payload，改 `fastboot_register` 尾调用注册 `boot`；
2. 用 magic + wrapper 跳过 stock `storage_image_loader`（绕开 AVB）；
3. 构造合法 v2 bootimg：`kernel=gzip(BootShim+FD)`、`kernel_addr` 必须等于
   LK `mb_kernel` 期望地址、`ramdisk_addr` 非 0、DTB 紧随 kernel；
4. 在 dtbo overlay（可选）与 bootconfig 追加调用点加 magic 门控钩子；
5. 通过 LK 自己的 `SMC 0xC2000115` 交棒 ATF，BootShim 搬 FD 到 UEFI 入口。

**三个最容易踩的坑**：magic 不能覆盖 `g_boot_info`（本机曾把 `dtb_size`
写成 `"-BOO"`，overlay 必失败）；DTB 不要多补 0x1000 gap；`kernel_addr`
与 `mb_kernel` 固定区域必须一致。

## 关键结论（详见 docs/）

- LK 是 AArch64、自重定位 (PIE) 裸机镜像，MTK MKIMG 多子分区容器：
  `lk / cert1 / cert2 / bl2_ext / cert1 / cert2 / aee / cert1 / cert2 / lk_main_dtb / cert1 / cert2`。
- `boot` 命令的主机端（项目内 fastboot-rs）已存在：先 `download:` 下载，再发送裸命令 `boot`。
  因此 LK 侧只需要注册一个 **前缀为 `boot`（不带冒号）** 的 handler。
- LK 正常启动路径完整存在：`load_bootinfo_from_hdr` → `bootinfo_set_image` →
  `boot_linux_from_storage` → `boot_linux_fdt`。`fastboot boot` 可以复用这条路径，
  只需把 boot 镜像来源替换为 fastboot 下载缓冲区。
- 设计采用“先让原 storage loader 加载 vendor_boot/环境 → 覆盖 boot 头与镜像基址 →
  再调用原 `boot_linux_from_storage`”的方式，最大程度复用原 ramdisk/DTB 拷贝与 cmdline 逻辑。
- payload 不能放数据尾部（LK 将数据页映射为 NX，v1 因此 instruction abort）；v2 放在 VBAR=0x1000 同页的可执行零洞 `0x1880..0x1bb6`。

## 构建

```bash
# 依赖: aarch64-linux-gnu-{as,ld,objcopy,nm}, python3
make payload          # 编译 AArch64 payload
make image            # 注入并 CERT2 重签，输出 dist/
make verify           # 静态校验（容器/补丁/CERT2/载荷）
```

输入/输出路径通过命令行覆盖：`python3 scripts/patch_lk.py --input <lk.bin>
--output dist/lk.img`；`scripts/make_bootimg_v2.py` 需要自备 BootShim、
UEFI FD 与 stock vendor DTB。

## 当前成品

### UEFI RAWBOOT（2026-10-30，当前主线）

```
dist/lk.img     刷 lk_a 的 LK v5（magic 迁址 + overlay/bootconfig 钩子）
sha256 6aea4c4258ac0f639e1ec2ce103db7b54eb607435173a26fb5f803e8e20a8ddd

dist/uefi.img   合法 v2 boot image（kernel_addr=0x40000000，DTB 紧接 kernel）
sha256 9b89578a61e7150ecbc7e84e17a66744fae7abef41294949c869cb2a262abdf6

dist/uefi.fd               iQOO Z8 UEFI 本体（7 MiB，DEBUG）
sha256 7f6ca27d59e4bac7040b6ce05f34c14779d9209e22263fed313416fe29b40adc
```

- LK v3e 的 `boot` 支持 RAWBOOT 与 **v2 bootimg**；`uefi.img` 走后者：
  LK `load_bootinfo`/`bootinfo_set_image`/`boot_linux_from_storage`，
  解压 gzip kernel 到 `0x40080000`、带 DTB，经 `0x1CA10` →
  `SMC 0xC2000115` 交 ATF；同时兼容
  platform-tools 自动包出的 `ANDROID!` boot.img（kernel 在 +0x800）。
- v4/v5：magic 从 `g_boot_info+0x668` 迁到 `LK+0xf3100`（旧位置覆盖
  v2 头 `dtb_size`，导致所有 overlay 都报 Bad fdt size）；0xc3f0 的 dtbo
  overlay 调用改为 `overlay_hook`，0xcb7c 的 bootconfig 追加改为
  `bootconfig_hook`（fastboot 路径没有 vendor ramdisk 映射）。两者都在
  magic 命中时才改变行为，正常 boot 原样尾调用原函数。镜像
  `kernel_addr=0x40000000` 以匹配 LK 的 mb_kernel 固定区域。
  根因与刷写说明见 docs/11。
- UEFI 为 iQOO Z8 专用内存图/显示/UFS 基址，DEBUG DXE 日志直接上屏；
  首版剔除 UFS/SCSI/ext4，PrePi 早期关看门狗。
- **2026-10-30：v5 真机成功启动 UEFI**（`lk-v5.img` + `uefi.img`，
  链路见 docs/11）。
- **2026-10-30：v5 真机成功启动 UEFI**（`lk-v5.img` + `uefi.img`，
  链路见 docs/11）。
- 刷写/启动/回滚见 [docs/11](docs/11-rawboot-uefi-flash.md)。
- 只生成文件，不执行刷写。

### Android fastboot boot（v2，已删除）

v2 产物已清理；仅保留历史哈希 `984c2f60…a90018`，详见 docs/09。

## 文档

- [01 镜像/内存布局](docs/01-image-layout.md)
- [02 Fastboot 注册与分发](docs/02-fastboot.md)
- [03 启动流程与接入点](docs/03-boot-flow.md)
- [04 fastboot boot 实现与验证](docs/04-fastboot-boot-implementation.md)
- [05 64-bit kaeru 移植研究](docs/05-kaeru-arm64-port.md)
- [06 LK 运行全景（引导链/A-B/AVB/解锁/存储/日志）](docs/06-lk-runtime-overview.md)
- [07 首次真机事故：instruction abort @0xcef90 与修复](docs/07-expdb-root-cause-and-fix.md)
- [08 汇编级 LK 模拟器（RX/RW 权限 + NX 负向用例）](docs/08-assembly-simulator.md)
- [09 v2 真机：AVB NULL deref 根因](docs/09-fastboot-boot-realdevice-avb.md)
- [10 UEFI 路线决策：LK RAWBOOT → ATF SMC → pearl EDK2](docs/10-uefi-rawboot-decision.md)
- [11 UEFI RAWBOOT 首启：成品与刷写说明](docs/11-rawboot-uefi-flash.md)
- [12 移植指南：给 LK 加 fastboot boot + UEFI 引导](docs/12-porting-guide.md)
- [13 长文：iQOO Z8 上 fastboot boot 临时启动与 UEFI 引导](docs/13-longread-fastboot-boot-uefi.md)
- [函数/全局偏移表](notes/function-map.md)
- [进度日志 STATUS](STATUS.md)
- [交接日志 HANDOVER](HANDOVER.md)

## 参考项目

逆向与 UEFI bring-up 过程中参考了以下公开项目。仅作方法参考，仓库不包含
这些项目的代码、固件或签名材料。

**LK / bootloader**

- [R0rt1z2/kaeru](https://github.com/R0rt1z2/kaeru) — ARMv7 LK 注入框架
- [R0rt1z2/sprig](https://github.com/R0rt1z2/sprig) — ARMv8 bl2_ext 路线
- [R0rt1z2/fenrir](https://github.com/R0rt1z2/fenrir) — EL3 漏洞 PoC（已归档）
- [R0rt1z2/lkpatcher](https://github.com/R0rt1z2/lkpatcher) — LK 容器/证书处理
- [s0meguy1/kansas-unlock](https://github.com/s0meguy1/kansas-unlock) — 新平台 LK cert 路线

**UEFI / EDK2**

- [CrackerCat/EDK2-Xiaomi-MediaTek-MT6895](https://github.com/CrackerCat/EDK2-Xiaomi-MediaTek-MT6895)
  — pearl (MT6895) EDK2 平台，本仓库 `iqooz8Pkg` 的基础
- [stanveyjiang/uefi-camellia](https://github.com/stanveyjiang/uefi-camellia)
  — MT6833 UEFI 热跳与 handoff 方法
- [soundrust5/Port-woa-uefi-Xiaomi-14T](https://github.com/soundrust5/Port-woa-uefi-Xiaomi-14T)
  — MT6897 UEFI/Windows bring-up 参考
- [linux-mediatek/edk2-mtk](https://github.com/linux-mediatek/edk2-mtk)
- [WP4Android/edk2-mediatek](https://github.com/WP4Android/edk2-mediatek)

**XNU / iOS**

- [oosexgang/hakios-xnu-kernel](https://github.com/oosexgang/hakios-xnu-kernel)
- [oosexgang/hakios-mt6768](https://github.com/oosexgang/hakios-mt6768)
- [oosexgang/hakios-uefi](https://github.com/oosexgang/hakios-uefi)
- [dipa-studio/ios-sweet](https://github.com/dipa-studio/ios-sweet)
- [MakrSas/ios-topaz](https://github.com/MakrSas/ios-topaz)

## 验证

```bash
make verify
# = verify_output.py + lk_sim.py + emulate_payload.py + lk_flow_sim.py
#   + emulate_overlay.py
```

- **lk_sim.py**：按 LK 的 RX/RW 页权限执行成品实际字节；负向用例在 0xcef90 NX 取指时抛 UC_ERR_FETCH_PROT；
- Unicorn 从成品镜像执行真实 LK 注册函数 0x8120 -> 0x81d8 -> payload stub；
- wrapper/handler 控制流仿真；
- **emulate_overlay.py**：执行真实 0xc3dc..0xc3f4 调用点 + v3f 钩子，覆盖
  正常放行、基址修正、overlay 失败回退、无 FDT、真实 uefi.img 与
  padded uefi.img；
- CERT2、part 链、补丁点、未变子分区逐字节校验；
- 项目外部 `verify_mtk_image.py` 交叉验证：CERT1/CERT2 signature OK，Result VALID。

> 本仓库只生成镜像，不执行任何刷写。刷写风险自负，务必先备份原 LK。
