# 02. Fastboot 命令注册与分发

## 1. 数据结构（LK 0x4be8 `fastboot_register`）

```c
// 分配 0x28 字节，插入到全局链表头 [0xf20a8]
struct fastboot_cmd {
    struct fastboot_cmd *next;   // +0x00
    const char *name;            // +0x08
    uint32_t name_len;           // +0x10 (strlen(name))
    uint32_t flag1;              // +0x14  allowed_when_security_on?
    uint32_t flag2;              // +0x18  forbidden_when_lock_on?
    void *handler;               // +0x20
};
```

- 注册函数 `0x4be8`：`void fastboot_register(name, handler, w2, w3)`。
- 命令表头：`LK_base + 0xf20a8`；新命令头插。

## 2. 注册函数 0x8120（原 LK）

原函数按顺序注册 6 条命令（调用 `0x4be8`）：

| 命令 | handler | flag1 | flag2 |
|---|---:|---:|---:|
| `download:` | 0x81dc | 1 | 0 |
| `flash:` | 0x8294 | 1 | 1 |
| `erase:` | 0x8908 | 1 | 1 |
| `oem ultraflash:` | 0x89d4 | 1 | 1 |
| `oem ultraflash_en` | 0x8b78 | 1 | 1 |
| `ultraflash:` | 0x89d4 | 1 | 1 |

最后一条 `ultraflash:` 是 **尾调用**：`0x81d8: b 0x4be8`。注册函数在
`0x81d4` 已恢复 x29/x30/sp，因此该 tail 时 x30 就是调用者的返回地址。

## 3. 命令分发与 handler ABI

- 主循环约 `0x527c..0x550c`；命令匹配后：
  - `x0 = 输入命令串 + name_len`（参数，例如 `flash:boot` 的 `boot`）；
  - `x1 = [0xf20d0]`（fastboot download buffer）；
  - `x2 = [0xf2140]`（download size，u32）；
  - `x8 = node->handler; blr x8`。
- 标志门（已用受控仿真验证）：

```
security_on = 1, vivo state: 1=locked, 3=unlocked
if security_on:
    if flag1 == 0:      allow = (state == unlocked)
    elif flag2 == 0:    allow = True
    else:               allow = (state == unlocked)
else:
    if flag2 == 0:      allow = True
    else:               allow = (state == unlocked)
```

效果：

| 命令 | locked | unlocked |
|---|---|---|
| `download:` (1,0) | 允许 | 允许 |
| `flash:`/`erase:` (1,1) | 拒绝 | 允许 |
| `boot` (1,0) | **允许** | 允许 |

这与项目逆向笔记中「flag2==0 的命令无锁门」一致。

## 4. 主机端行为

`tools/vivo-unlocker/fastboot-rs`：

```rust
pub const FB_CMD_BOOT: &str = "boot";
...
driver.download(&data).await?;   // download:<size> + DATA + OKAY
driver.boot().await?;            // 发送 "boot"（无冒号、无参数）
```

因此 LK 侧必须注册 **前缀为 `boot`（不带冒号）** 的命令；注册
`boot:` 不会被匹配。handler 在命令被解析后拿到之前 download 的
buffer/size。

## 5. 本方案的注册改动

只改 `0x81d8` 一条 4 字节指令：

```
原: 17fff284  b 0x4be8             ; ultraflash: 注册的尾调用
新: 17ffe5aa  b 0x1880            ; -> payload stub
```

payload stub（0x1880，可执行代码洞）：

1. 先执行被替换的 `ultraflash:` 注册（原 x0/x1/w2/w3 仍在）；
2. 再 `fastboot_register("boot", boot_handler, 1, 0)`；
3. 返回原注册函数调用者。

这是“新增命令”而非“替换/删除原命令”。`stub` 对 x19-x28 无副作用；
`fastboot_register` 遵循 AAPCS64 保存 callee-saved。

### 注册仿真（真实 LK 代码）

`scripts/lk_flow_sim.py` 用 Unicorn 从成品镜像直接执行 **0x8120**，
拦截 0x4be8，实际跑到 0x81d8 -> payload stub：

```
download:              handler=0x0081dc f1=1 f2=0
flash:                 handler=0x008294 f1=1 f2=1
erase:                 handler=0x008908 f1=1 f2=1
oem ultraflash:        handler=0x0089d4 f1=1 f2=1
oem ultraflash_en      handler=0x008b78 f1=1 f2=1
ultraflash:            handler=0x0089d4 f1=1 f2=1
boot                   handler=0x0cf00c f1=1 f2=0
```

原 6 条命令的 name/handler/flags 全部不变；boot 头插。
分发模型验证 locked 状态下 `boot` 允许、`flash/erase` 拒绝，
unlocked 全部允许。

## 6. 日志

handler 所有阶段通过 LK `printf`（0x6b570）输出，前缀
`kaeru-fb-boot:`。这些日志进入 LK log buffer，异常/重启后由 expdb
记录，便于用 `oem dump_pllk_log` / expdb 转储观察：

```
kaeru-fb-boot: start size=0x...
kaeru-fb-boot: storage loader ret=...
kaeru-fb-boot: hdr=... kaddr=... raddr=... rsize=... dtb=...
kaeru-fb-boot: magic set, entering normal boot flow
kaeru-fb-boot: calling boot_linux_from_storage
kaeru-fb-boot: skip storage reload (magic)     # wrapper 每次跳过
kaeru-fb-boot: failed (code), back to fastboot  # 返回时
```
