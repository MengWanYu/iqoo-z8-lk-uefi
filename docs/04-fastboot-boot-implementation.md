# 04. `fastboot boot` 实现与验证（v2）

## 1. 产物

```
dist/iqooz8-os3-fastboot-boot-16MB.img
size   16,777,216 (0x1000000)
sha256 984c2f60d4b0ea02084acb56632f278fed49258fd73325fc8426e48af4a90018
```

payload：822 B (0x336)，sha256
`08ad4906ecc0ec606cfd763b3f824325921c61d40261ae02448ee6ffd265fc92`。

> v1（payload 放在数据尾部 0xcef90）已在真机 expdb 中证明会
> `instruction abort: PC at ...0xcef90` 并 panic；v2 已改为可执行代码洞，
> 详见 `docs/07-expdb-root-cause-and-fix.md`。

## 2. Payload 布局（链接地址 = LK 镜像内偏移 0x1880）

| 符号 | 地址 | 作用 |
|---|---:|---|
| `payload_base` / `stub` | 0x1880 | 被 0x81d8 分支进入；补做 ultraflash 注册，再注册 boot |
| `load_wrapper` | 0x18a8 | 被 0xd12c/0xd15c 调用；有 magic 则返回 0，否则尾调用 0x51a04 |
| `boot_handler` | 0x18f8 | `boot` 命令 handler |
| `boot_cmd` | 0x1a58 | `"boot\0"` |
| `magic` | 0x1a60 | `"KAERU-FB-BOOT!!!"`（16 B） |

- 0x1880 位于 `VBAR_EL1=0x1000` 的 16 个异常向量（0x1000..0x1800）之后、
  0x1800..0x1878 的异常处理代码之后；0x187c..0x2400 是全零区，无代码/数据/
  字面量/relocation 引用。
- payload 0x1880..0x1bb6 全部落在 **0x1000..0x1fff 这个可执行页**内；
  代码和字符串同页，不再放在 NX 数据尾部。
- **lk dsize 保持 0xcef90**，不扩展镜像；仅 CERT2 重签增长。

## 3. 代码结构

### stub（0x1880）

```
stp x29,x30,[sp,#-16]!
mov x29,sp
bl  fastboot_register          ; 原 x0/x1/w2/w3 = ultraflash: 注册参数
adr x0, boot_cmd
adr x1, boot_handler
mov w2,#1
mov w3,#0
bl  fastboot_register          ; boot, locked 可用
ldp x29,x30,[sp],#16
ret
```

### load_wrapper（0x18a8）

```
; x8 = LK_base = payload_base - 0x1880
; 比较 g_boot_info+0x668 (0xf2e90) 的 16 B
;   == magic -> log "skip storage reload" ; w0=0 ; ret
;   != magic -> b 0x51a04 (原 storage loader)
```

正常启动 magic 不存在，等价于原 `bl 0x51a04`（尾调用，LR 不变）。
fastboot boot 时 magic 已设置，跳过从存储重新加载。

### boot_handler（0x18f8）

```
x19 = download_base; x20 = download_size
x27 = LK_base (payload_base - 0x1880)
w28 = 旧 boot mode; [0xf3718] = 0 (normal)
if size < 0x67c -> fail(-3)
log "start size=0x%x"
w0=0; bl 0x51a04            ; storage loader(mode 0=boot)，加载 stock boot+vendor
w25 = ret; log "storage loader ret=%d"
x0=download; bl 0x9d00      ; 解析下载的 boot 头
if fail -> fail(-2)
x22 = [0xf3710]             ; vendor_boot base（若 v4）
x0=download; x1=x22; bl 0xa6ec   ; 设置 boot base=下载缓冲
call helpers (0x9ee8/0x9f94/0xa240/0xa5f4/0xa68c) + log "hdr=... kaddr=..."
[0xf3718] = 0               ; loader 可能改过模式，再次强制 normal
write magic -> g_boot_info+0x668
log "magic set..." / "calling boot_linux_from_storage"
bl 0xd0d4                   ; 原正常启动主流程；wrapper 跳过其 loader 调用
w24 = ret
clear magic; restore old mode; log "failed (%d), back to fastboot"
```

## 4. 代码补丁点

| 地址（lk data offset） | 原指令 | 新指令 | 作用 |
|---:|---|---|---|
| 0x81d8 | `0x17fff284` b 0x4be8 | `0x17ffe5aa` b 0x1880 | 注册函数尾 -> stub |
| 0xd12c | `0x94011236` bl 0x51a04 | `0x97ffd1df` bl 0x18a8 | loader 调用 #1 -> wrapper |
| 0xd15c | `0x9401122a` bl 0x51a04 | `0x97ffd1d3` bl 0x18a8 | loader 调用 #2 -> wrapper |

除这 12 字节和 0x1880..0x1bb6 的 payload 外，原 lk data 与输入逐字节一致
（verifier 证明）。

## 5. 镜像重建与 CERT2 重签

1. 提取 lk 子分区（part_hdr + data + cert1 + cert2）。
2. 将 payload 注入 lk data 0x1880（cave 全零断言）；lk dsize 不变 0xcef90。
3. 重建 part 链：只有 CERT2 重签增长（0x419 -> 0x473），bl2_ext/aee/
   lk_main_dtb 顺移。
4. `mtk_img.sign_image_bytes(..., legacy=False)`：CVE-2023-20696 overlay，
   保留原证书 DER 与签名。
5. 填充/截断到 16MiB；part 链校验。
6. 输出 manifest（input/output/payload hash、补丁点、cave、part 表）。

## 6. 验证结果（本地，无刷写）

- **CERT1/CERT2 签名**：项目外部 `verify_mtk_image.py`：
  `CERT1 signature: OK`、`CERT2 signature: OK`、
  `Image header hash: OK`、`Image data hash: OK`、`Result: VALID`。
- **补丁点**：三处原指令/目标/新目标校验通过；lk data 差异仅 3 条指令
  + 0x1880..0x1bb6 payload。
- **未变子分区**：bl2_ext / aee / lk_main_dtb 的 SHA256 与输入一致。
- **payload 位置**：0x1880..0x1bb6 与 payload.bin 逐字节一致；输入该区域全零。
- **真实 LK 注册函数仿真**（Unicorn）：从成品执行 0x8120 -> 0x81d8 -> 0x1880；
  记录 7 次注册；原 6 条命令 name/handler/flags 不变，boot(1,0) 头插。
- **分发门仿真**：locked+security on 下 download/boot 允许，flash/erase 拒绝；
  unlocked 全部允许。
- **payload 控制流仿真**：stub 注册参数、wrapper 有/无 magic、handler
  调用链、mode=0、magic 设置/清理、日志全部通过。
- **汇编级 RX/RW 仿真（lk_sim.py）**：按 LK 的可执行/数据页权限执行成品实际
  字节；v1 的 0xcef90 负向用例抛 `UC_ERR_FETCH_PROT`（PC 0xcef90），v2 正向
  7 条注册与 handler 全部通过。

## 7. 构建

```bash
make payload
make image
make verify
```

依赖：`aarch64-linux-gnu-binutils`, `python3-unicorn`，项目内
`tools/lk-patcher-master`（纯标准库）。

## 8. 风险 / 真机验证

1. **当前设备仍是 v1**：先恢复已知良好 LK，再刷 v2。
2. **代码页执行权限**：v2 代码与 VBAR 向量同页，理论上可执行；若 expdb 仍
   报 instruction abort at 0x…1880，则需改页表/换洞。
3. **fastboot 环境调用 storage loader(0)**：日志 `storage loader ret=...`。
4. **v4 vendor_boot**：`fastboot boot boot.img` 使用 stock vendor_boot；
   若 vendor 损坏则失败。
5. **下载缓冲对齐/大小**：boot_linux_fdt 以 download buffer 作为镜像基址；
   日志 kaddr/raddr 可判。
6. **cmdline**：v4 使用 stock vendor cmdline；v2 使用下载 boot.img cmdline。
7. **失败时不会主动回 OKAY/FAIL**：host 可能超时；设备留在 fastboot。
8. **CERT2**：CVE overlay；目标 preloader 策略需接受（v1 已证明接受）。
