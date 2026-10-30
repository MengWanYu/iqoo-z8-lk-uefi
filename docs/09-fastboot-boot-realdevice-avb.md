# 09. v2 真机第二步：fastboot boot 已进入 handler，但 storage loader/AVB panic

## 结论

- v2 的 NX 修复有效：设备能进 fastboot，官方 fastboot 的 `download:` 与 `boot`
  都被接收；expdb 里出现我们的 `kaeru-fb-boot: start size=0x6000000`。
- 但这次没有到内核：handler 先调用的 stock `storage_image_loader(0)` 在
  locked/AVB 路径里 NULL deref，panic/HALT，USB 断开，所以 host 显示
  `Booting FAILED (Status read failed (Too many links))`。
- 这不是 fastboot 不认命令，也不是 CERT/NX 问题。

## expdb 证据（最后一次 boot）

```
fastboot: download:06000000
Resp: DATA06000000
download_base: 0x8064b010, length: 0x6000000
fastboot: boot[len:4]
fastboot:[cmd:boot]-[arg:]
kaeru-fb-boot: start size=0x6000000
check_device_unlock_auth verify failed, do nothing in lock!
check_device_unlock_auth done
AVB: force img_auth_required = 1
...
AVB: boot_b: Hash of data does not match digest in descriptor.
...
heap_grow:490: failed to grow kernel heap by 0x8001000 bytes
AVB: avb_util.c:223: ERROR: Failed to allocate memory.
data fault: PC at 0xffff000080016dbc, FAR 0x10, iss 0x4
x0 0x0 ...
elr 0xffff000080016dbc
panic (caller 0xffff00008000125c): die
HALT: action = 0, reason = 9
```

## 根因

1. 设备处于 locked；`check_device_unlock_auth` 失败，AVB 仍强制开启
   (`AVB: force img_auth_required = 1`)。
2. handler 为了拿 vendor_boot/cmdline，调用了 stock `storage_image_loader(0)`。
   该函数会走正常启动的 AVB 校验，校验的是**存储里的 boot_b**，不是我们下载的
   boot.img。
3. 当前 boot_b 数据与 vbmeta 描述符 hash 不一致：
   `boot_b: Hash of data does not match digest in descriptor.`
   （boot 分区被 Magisk/其它修改过）
4. 同时 96MB boot 让 AVB 需要扩充 ~0x8001000 bytes 内核堆，`heap_grow` 失败；
   `avb_slot_verify` 返回错误/NULL。
5. LK 的 AVB 结果处理函数（0x16d98，从 storage loader 0x51da8 调用）未判空，
   执行 `ldr x8,[x0,#16]` 时 x0=0 → FAR 0x10，data abort → panic/die。
   这正是项目文档提到的 vivo `load_vfy_boot` NULL deref 问题。

## 对两个目标的影响

### Android Magisk boot

- 当前 v2 的初始 storage loader 会校验已修改的 boot_b；即使不看对齐/基址，
  AVB 这一关就会死。
- 要支持，需要：
  - 跳过 storage loader/AVB；或
  - 在 LK 里应用 `avb_allow_error`（`--unlockless` 补丁）并容忍 hash mismatch；
  - 且 v4 仍需 stock vendor_boot（可从分区直接读，不走 AVB）。

### UEFI / XNU raw payload

- 不应该调用 storage loader/AVB；
- 需要新增 **raw boot 分支**：
  ```
  RAWBOOT! (8B)
  u64 load_addr
  u64 entry
  u64 dtb_addr
  u64 payload_size
  payload...
  ```
  handler 在 Android boot magic 检查之前识别 RAWBOOT：
  - 不调用 0x51a04 / load_bootinfo / boot_linux_from_storage；
  - 将 payload 复制到 load_addr，flush D/I cache；
  - 设置 x0=dtb_addr，跳 entry；
  - 日志：`kaeru-fb-boot: raw load=... entry=... size=...`。
- 这是下一步实现方向；具体 load_addr/entry/dtb 由 UEFI payload 决定。

## host 错误解释

`Booting FAILED (Status read failed (Too many links))` 是设备 panic/reboot 导致
USB 断开；不是 fastboot 命令未识别。成功跳内核时也会断开，但本次 expdb 明确
显示是 AVB NULL deref，不是内核启动。
