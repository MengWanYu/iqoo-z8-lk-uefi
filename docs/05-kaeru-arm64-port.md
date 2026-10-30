# 05. 64-bit MTK / kaeru 移植研究

## 1. 结论

- 公开的 **kaeru 只支持 ARMv7 (32-bit Thumb) LK**；本机 LK 是 **AArch64 +
  bl2_ext + SBC** 的新引导链，不能直接使用 kaeru。
- 公开的 ARM64 “kaeru 后继”最接近的是 **R0rt1z2/sprig**：替换 LK 容器中的
  `bl2_ext`，在 EL3 运行 payload，patch Preloader 关闭 SBC/SLA/DAA；它不继续
  正常启动，但能获得未签名 DA / 任意刷写能力。
- Roger 在 fenrir README 中明确：做过 ARM64 kaeru PoC，但不会公开。
- 本仓库的 `fastboot boot` payload 已经是一个**最小化的 ARM64 kaeru-style
  LK 注入框架**：容器手术 + 代码洞注入 + 注册表/调用点 patch + 运行期日志 +
  CERT2 重签。它是把 kaeru 机制迁移到 64 位 LK 的第一块可用积木。

## 2. 32-bit kaeru 与本 LK 的差异

| 维度 | kaeru (ARMv7) | 本 LK (AArch64) |
|---|---|---|
| 指令 | Thumb-2，BL 两条半字 | 固定 32-bit，BL imm26 |
| 指针 | 32-bit，Thumb 位 `|1` | 64-bit，无 Thumb 位 |
| 重定位 | 固定基址/相对简单 | 自带 relocation 表 (0xb1000)，PIE |
| 引导链 | Preloader -> LK | Preloader -> bl2_ext(EL3) -> ATF/TEE/GZ -> LK |
| 验证 | seccfg/cert1/2 | SBC + CERT2（本输入已 AVB 放行） |
| 注入 | 追加 stage1 + 子分区 | 容器尾部 payload + 代码洞；可扩展 stage1 |
| Hook | Thumb BL/NOP/返回序列 | AArch64 B/BL、LDR/BR veneer、NOP=0xD503201F |

## 3. 本 payload 已验证的 64 位能力

1. **容器手术**：解析 part_hdr 链，插入 payload，更新 dsize，后续子分区顺移。
2. **PIE 注入**：payload 链接在镜像偏移 0x1880（VBAR=0x1000 同页的可执行零洞），全部 PC 相对；随 LK 重定位。
3. **注册表插入**：在真实 fastboot 注册函数尾插入 stub，先补做原注册，再注册
   `boot`；Unicorn 从成品镜像执行 0x8120，验证 7 条命令。
4. **调用点 patch**：0xd12c/0xd15c 的 `bl storage_loader` 改为 wrapper；
   magic 未设置时尾调用原函数，正常启动不变。
5. **运行期状态**：g_boot_info/image base/boot mode 读写；128-bit magic 标志。
6. **日志**：stdout `printf` -> LK log buffer -> expdb；`kaeru-fb-boot:` 前缀。
7. **CERT2**：CVE-2023-20696 overlay 重签，全链 VALID。
8. **仿真**：Unicorn 验证 stub/wrapper/handler；真实 LK 注册函数冒烟。

## 4. 把 kaeru 完整迁移到本平台的路线

### 阶段 A：LK 级 payload 框架（本仓库已完成基础）

- AArch64 stage2：C + 少量汇编（GOT/重定位、cache、栈、日志）。
- 注入：优先镜像尾部（BSS 前）；不足时新增子分区 + stage1（参考 kaeru）。
- Hook API：
  - 表指针替换（app descriptor / command list）；
  - `BL` 调用点重定向（±128MB；超出用 `ldr x16, #8; br x16; .quad target` veneer）；
  - `FORCE_RETURN` = `mov w0,#imm; ret`；`NOP` = `0xD503201F`；
  - 特征码扫描（4-byte 指令，注意 ADRP/ADD 对、literal pool）。
- Fastboot API：0x4be8 注册；handler(arg, data, size)；本仓库 `boot` 为样例。
- 启动 API：load_bootinfo_from_hdr / bootinfo_set_image / boot_linux_fdt；
  本仓库的 wrapper + 正常启动流复用是参考实现。

### 阶段 B：通用化/多设备

- 每设备 profile：LK base、fastboot_register、loader、boot 函数、globals、
  boot mode 枚举、字符串/特征码；类似 kaeru defconfig。
- 版本兼容：字节模式 + 上下文校验；失败则拒绝输出（参考 lk-patcher 的
  profile 机制）。
- 日志与恢复：所有阶段 printf；错误返回 fastboot，不重启；expdb 记录。

### 阶段 C：EL3 / bl2_ext 路线（SBC/SLA/DAA）

- 若目标需要关闭 SBC、启动未签名 DA、自由 dump：走 **sprig 模式**：
  - 替换 LK 容器中的 `bl2_ext` 子镜像（EL3，AArch64）；
  - payload patch Preloader 内存中的 SBC/SLA/DAA 检查，跳回 Preloader handshake；
  - 设备会“变砖”直到恢复原 LK；不继续正常启动。
- 与 LK 级 payload 组合：先用 bl2_ext 路线获得刷写/调试能力，再刷 LK 级
  fastboot boot/调试镜像。
- 本平台 MT6896 的 bl2_ext 结构与 sprig 参考设备（MT6886/MT6989）同代；
  需按设备适配地址/偏移，未在本仓库验证。

### 阶段 D：kaeru 功能对齐

- 自定义 fastboot 命令、按键重映射、去警告、锁状态伪装、调试 hook。
- 对本 LK 的解锁/seccfg/AVB 已有项目研究（key 表、unlock2、set_active 等），
  可直接作为板级 patch 集。

## 5. 可行性评估

| 目标 | 可行性 | 说明 |
|---|---|---|
| LK 级 ACE / 自定义 fastboot | 高 | 本仓库已实现 boot 命令与调用点 hook，机制可复用 |
| 通用多设备 kaeru 框架 | 中 | 需每设备逆向/特征码；AArch64 无 Thumb 位，结构体 LP64 |
| EL3 bl2_ext (SBC/SLA/DAA) | 中 | sprig 有公开参考；需设备适配，风险高 |
| 完整 “kaeru for ARM64” 公开实现 | 无现成 | Roger 的 ARM64 PoC 未公开；需自行实现 |

## 6. 参考

- R0rt1z2/kaeru（ARMv7）
- R0rt1z2/sprig（ARMv8 bl2_ext）
- R0rt1z2/fenrir（EL3 漏洞 PoC，已归档）
- R0rt1z2/lkpatcher / liblk（LK 容器/证书）
- s0meguy1/kansas-unlock（新平台 LK cert 路线）
- 本项目 `tools/lk-patcher-master`（V6 容器/签名/profile）

## 7. XNU / UEFI 的 `fastboot boot` 扩展

当前 `boot` handler 复用 Android 正常启动流（`load_bootinfo_from_hdr` +
`boot_linux_from_storage` + `boot_linux_fdt`），目标是 Android boot.img。
若未来用于 XNU/UEFI 的临时调试，可增加 **raw boot 分支**：

1. 在下载镜像开头使用自定义 magic（例如 `RAWBOOT\0` + u64 load_addr + u64 entry + u64 dtb）。
2. handler 识别 magic 后：
   - `memcpy` 到目标物理地址（或使用下载缓冲本身）；
   - `dc cvau`/`ic ivau`/`dsb ish`/`isb` 维护缓存；
   - 可选设置 x0=dtb、x1=0 等 ABI；
   - `br entry`，不再返回 fastboot。
3. 失败则返回 fastboot 并打印 `kaeru-fb-boot:` 日志；expdb 可查。
4. 安全约束：只允许在明确授权的调试设备上使用；地址/镜像必须由操作者给出，
   不做任意地址猜测。

该分支与现有 Android boot handler 可共存（按 magic 分流），不影响原 LK 正常启动。
本仓库未实现 raw 跳转，以避免在本就不允许刷写的环境里引入未验证的任意执行路径。
