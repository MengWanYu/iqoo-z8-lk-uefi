# 08. 汇编级 LK 模拟器（RX/RW 权限 + NX 负向用例）

## 1. 为什么需要新的模拟器

v1 事故的根因是 payload 被放在 LK 的**数据页**（0xcef90，NX），而旧模拟器
（`emulate_payload.py` / `lk_flow_sim.py`）把所有内存都映射成
`UC_PROT_ALL`（可读/写/执行），因此**不可能发现 NX 取指异常**。

新模拟器 `scripts/lk_sim.py` 的核心变化：

- 按 LK 观测到的内存属性分页映射；
- 执行**成品镜像里的实际 lk 字节**，而不是把 payload 单独加载到任意地址；
- 增加 **v1 负向用例**，必须在模拟阶段触发 `UC_ERR_FETCH_PROT`；
- v2 正向用例必须在同一权限模型下完整跑通 0x8120 -> stub -> wrapper/handler。

## 2. 内存权限模型

依据：

- v1 expdb：`instruction abort: PC at 0xffff0000800cef90` → 0xcef90 数据尾
  对取指不可执行；
- VBAR_EL1 = 0x1000（代码 `adrp x8,#0x1000; msr vbar_el1,x8`），异常向量页
  0x1000..0x1fff 可执行；
- 代码函数（0x4be8/0x51a04/0x8120/0x9d00/0xd0d4 等）均 < 0xb1000；
- relocation 表在 0xb1000，之后为 data/BSS。

因此模拟器使用：

| 区域 | 权限 | 内容 |
|---|---|---|
| [0x000000, 0x0b1000) | RX | 入口、向量表(0x1000)、代码、rodata、v2 payload 0x1880 |
| [0x0b1000, 0x1000000) | RW (NX) | relocation 表、data/BSS、0xcef90 尾部（v1 payload 所在） |
| [0x1000000, 0x1200000) | RW | fastboot download buffer |
| [0x2e00000, 0x3000000) | RW | 栈 + sentinel |

说明：这是**基于现有证据的模型**，用于捕获 NX/RX 边界错误；真实 LK 的
页表属性仍以设备为准。

## 3. 实现方式

- 加载成品 `dist/iqooz8-os3-fastboot-boot-16MB.img` 的 lk 数据到 0；
- `mem_protect` 设置 RX/RW；
- 拦截 LK 服务函数（只拦截调用，保留真实 payload 指令）：
  - 0x4be8 fastboot_register
  - 0x51a04 storage_image_loader
  - 0x9d00 load_bootinfo_from_hdr
  - 0xa6ec bootinfo_set_image
  - 0xd0d4 boot_linux_from_storage
  - 0x9ee8/0x9f94/0xa240/0xa5f4/0xa68c helpers
  - 0x6b570 printf
- 执行：
  1. **正向注册**：PC=0x8120；真实 LK 注册函数 → 0x81d8（b 0x1880）→
     payload stub；必须得到 7 条注册，boot handler=0x18f8；
  2. **负向 v1**：复制 lk，改 0x81d8 为 `b 0xcef90`，把 payload 写到
     0xcef90（RW），执行 0x8120；必须抛 `UC_ERR_FETCH_PROT`，PC 在 0xcef90
     附近；
  3. **wrapper**：magic 未设置 → 调用 storage loader；设置 → 跳过并日志；
  4. **handler**：实际执行 0x18f8，设置 download buffer/globals，验证
     loader/parse/set_image/helpers/boot_from_storage、mode=0、magic、日志、
     失败清理。
- 静态检查：payload 0x1880..0x1bb6 必须在 RX 内；0x81d8/0xd12c/0xd15c
  分支目标正确；payload 不是全零。

## 4. 运行与预期输出

```bash
python3 scripts/lk_sim.py
# 或 make verify-sim
```

预期：

```
payload RX range: 0x1880..0x1bb6 (model RX end 0xb1000)
patch/branch static checks: OK
positive registration: OK, 7 commands, boot handler 0x18f8
negative v1: OK, UC_ERR_FETCH_PROT at PC 0xcef90 (matches expdb 0x…cef90)
wrapper RX/RW: OK (no magic -> loader; magic -> skip)
handler RX/RW: OK, calls=[printf, storage_loader, printf, load_bootinfo,
                         set_image, printf, printf, printf, boot_from_storage, printf]
ASSEMBLY-LEVEL LK SMOKE TEST PASSED (RX/RW enforced; v1 NX caught)
```

## 5. 这能防止什么 / 不能防止什么

能防止：

- payload/代码洞落在数据页（NX）——v1 事故的精确复现；
- 分支目标落 NX 区；
- 调用/返回路径跑出 RX；
- 写 RX 代码页（Unicorn 权限会报错）；
- 分支编码/补丁目标错误（静态检查 + 运行）。

不能替代真机：

- LK 真实页表属性/MMU 边界可能与本模型不同（当前模型基于 VBAR/expdb）；
- 不模拟 storage/USB/AVB/内核启动；
- `0xb1000` 边界是模型假设，若实际 RX 范围不同，需要调整；
- 真机仍需 expdb 验证。

## 6. 接入

- `Makefile`：`verify` = `verify-image` + `verify-sim` + `verify-emu` +
  `verify-flow`；
- `scripts/lk_sim.py` 是新的强制门禁：v2 必须通过，v1 负向必须失败。
