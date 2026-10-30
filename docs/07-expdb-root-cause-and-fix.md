# 07. 首次真机事故：instruction abort @ 0xcef90 与修复

## 1. 现象

- 刷入首版（v1，payload 在 lk 数据尾部 0xcef90）后：
  - 能亮 logo；
  - 无法进入/暴露 fastboot（USB 无 fastboot 设备）。
- 用户回读 expdb：`fastboot_boot_work/expdb/expdb.img`。

## 2. expdb 证据

关键日志（按出现顺序）：

```
[SEC] lk cert chain vfy pass
[SEC] image lk header auth pass
[SEC] image lk auth pass
...
notify_enter_fastboot:94: Notify enter fastboot.
starting app fastboot
wait_for_enter_fastboot:100: Wait for enter fastboot event...
wait_for_enter_fastboot:103: Ready to enter fastboot...
instruction abort: PC at 0xffff0000800cef90
panic (caller 0xffff00008000125c): die
```

## 3. 根因

- LK 运行时基址 + 0xcef90 = `0xffff0000800cef90`。
- 0xcef90 正是 v1 payload 的第一条指令（stub）。
- 刷入/签名完全正常：preloader 已 `lk cert chain vfy pass` / `image lk auth pass`。
- fastboot app 初始化时执行注册函数 0x8120；其尾部 0x81d8 已被改为
  `b 0xcef90`；CPU 在 0xcef90 取指时触发 **instruction abort**。
- 说明 LK 的 MMU 把该区域（镜像数据尾部/数据页）映射为 **不可执行 (NX)**，
  或未映射。v1 把代码放在了数据段，取指即异常；fastboot 进程 panic，logo
  停留在屏幕上，fastboot 无法启动。

结论：**不是证书/刷写/AVB 问题，是 payload 放置位置不在可执行页。**

## 4. 修复（v2）

把 payload 移到入口代码段内的可执行零洞：

- LK 的异常向量表 `VBAR_EL1 = 0x1000`（0x1000..0x1800，16 个向量）。
- 0x1800..0x1878 有少量异常处理代码；随后 **0x187c..0x2400 是一段全零
  区域**（0xb84 B），无 ADRP/ADR/BL/B/LDR-literal 引用，也无 relocation
  指针引用。
- 该区域与向量表在 **同一个 4 KiB 页 (0x1000..0x1fff)**，向量取指已证明该页
  可执行；因此把 payload 放在 **0x1880**。
- payload 822 B，结束于 0x1bb6，全部代码+字符串都在 0x1000 页内；
  不跨越页、不碰向量表、不改 lk dsize。

新布局：

| 符号 | 地址 |
|---|---:|
| payload_base / stub | 0x1880 |
| load_wrapper | 0x18a8 |
| boot_handler | 0x18f8 |
| boot_cmd | 0x1a58 |
| magic | 0x1a60 |

补丁：

- 0x81d8: `0x17fff284` -> `0x17ffe5aa` (`b 0x1880`)
- 0xd12c: `0x94011236` -> `0x97ffd1df` (`bl 0x18a8`)
- 0xd15c: `0x9401122a` -> `0x97ffd1d3` (`bl 0x18a8`)

lk dsize 保持 **0xcef90**；只有 CERT2 使用 CVE overlay 重签增长（0x419 ->
0x473），后续子分区顺移。BSS/0xcef90 之后的原数据不动。

新产物：

```
dist/iqooz8-os3-fastboot-boot-16MB.img
size   16,777,216
sha256 984c2f60d4b0ea02084acb56632f278fed49258fd73325fc8426e48af4a90018
```

## 5. 修复验证

- 0x1880..0x1bb6 在输入镜像中全零，且无代码/数据引用；
- payload 字节与 `build/payload.bin` 一致；
- 0x81d8/0xd12c/0xd15c 三条分支目标正确；
- 外部 `verify_mtk_image.py`：CERT1/CERT2 signature OK，Result VALID；
- Unicorn 从成品执行真实 0x8120 -> 0x81d8 -> 0x1880，原 6 条命令不变、
  boot(1,0) 注册成功；
- wrapper/handler 控制流仿真通过（含 magic/日志/清理）。

## 6. 真机恢复与测试建议

1. 当前设备仍运行 v1（fastboot 不可用）。先用已知良好的 LK（例如
   `images/lk_os3_setactive_keyswap_16MB.img`）通过 FlashTool/BROM 恢复，
   确认能进 fastboot/系统。
2. 刷入 **v2**（`lk_os3_fastboot_boot_16MB_v2.img`）到当前槽 `lk_a`。
3. 正常开机验证原命令；`fastboot boot boot.img`。
4. 若 v2 仍看 logo 且无 fastboot，回读 expdb：
   - 若异常 PC 不再是 0x…0cef90，而是 0x…001880/0x…0018xx，说明该页执行
     权限仍不符合预期，需要进一步改页表/换代码洞；
   - 若进入 fastboot，关注 `kaeru-fb-boot:` 日志。
