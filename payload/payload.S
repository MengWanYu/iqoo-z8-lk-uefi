/*
 * iQOO Z8 / MT6895 OS3 LK - fastboot RAWBOOT payload (v3)
 *
 * Linked at LK image offset 0x1880, inside the executable zero cave after
 * the exception vectors (VBAR=0x1000).  Position independent: only
 * PC-relative branches/ADR; no relocations.
 *
 * fastboot "boot" handler expects:
 *   x0 = arg, x1 = download_base, x2 = download_size
 * and receives a raw payload:
 *   "RAWBOOT!" (8 bytes)
 *   u64 load_addr   (0 = execute in place; ignored)
 *   u64 entry       (0 = payload start; ignored)
 *   u64 dtb_addr    (passed to ATF as x2)
 *   u64 payload_size
 *   payload bytes   (BootShim + UEFI FD; executed in place)
 *
 * The handler reuses LK's own final boot sequence (0x1CA10): quiesce,
 * disable caches, VA->PA, trampoline, SMC 0xC2000115 to ATF.  ATF erets
 * to the payload with MMU/caches off; BootShim copies the FD to
 * 0x50000000 and jumps to its FV entry.
 */

    .arch armv8-a

    .equ PAYLOAD_OFF,   0x1880
    .equ SMC_STUB_OFF,  0xd0c8          /* LK: mov x4,#1; smc #0; ret */
    /* LK offset 0xf3100 = vendor_boot header copy +0x258.  The old slot
     * (g_boot_info+0x668) overlapped the v2 header dtb_size at +0x670 and
     * poisoned it with "-BOO" (0x4F4F422D), so every dtbo overlay failed
     * with Bad fdt size.  ANDROID! images never write the vendor header. */
    .equ MAGIC_OFF,     0x100            /* + 0xf3000 = 0xf3100 */
    .equ BOOT_MODE_OFF, 0x718           /* 0xf3718 - 0xf3000 */

    .section .text.start, "ax"
    .global payload_base
    .global stub
payload_base:
stub:
    /* 0x81d8 was: b fastboot_register (tail call for "ultraflash:").
     * Perform that registration first, then add "boot". */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      fastboot_register
    adr     x0, boot_cmd
    adr     x1, boot_handler
    mov     w2, #1
    mov     w3, #0
    bl      fastboot_register
    ldp     x29, x30, [sp], #16
    ret

    .text
    .global load_wrapper
load_wrapper:
    /* Called from 0xd12c / 0xd15c.  If our bootimg handler published the
     * magic, skip the storage loader and let boot_linux_from_storage use
     * the already-parsed download image.  Normal boot keeps the loader. */
    adr     x8, payload_base
    mov     x9, #PAYLOAD_OFF
    sub     x8, x8, x9
    add     x9, x8, #0xf3000
    add     x9, x9, #MAGIC_OFF
    adr     x10, magic
    ldp     x11, x12, [x10]
    ldp     x13, x14, [x9]
    cmp     x11, x13
    b.ne    1f
    cmp     x12, x14
    b.ne    1f
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    adr     x0, msg_skip
    bl      lk_printf
    ldp     x29, x30, [sp], #16
    mov     w0, #0
    ret
1:
    b       storage_image_loader

    .text
    .global overlay_hook
overlay_hook:
    /* Called from 0xc3f0 in boot_linux_fdt instead of the stock ufdt
     * wrapper (0x72700):
     *   x0 = base fdt, w1 = base size, x2 = overlay, w3 = overlay size,
     *   x4 = &out.
     *
     * Normal boot (magic clear): tail-call the stock wrapper with the
     * original arguments.  RAWBOOT-UEFI: LK's v2 layout math adds one
     * page for each zero-sized ramdisk/recovery_dtbo section, so its
     * base pointer lands past the real FDT.  Locate the FDT by magic +
     * header dtb_size, overlay it, and fall back to a plain FDT (copied
     * into LK's own pointer slot so its free() stays valid) if the
     * overlay fails. */
    stp     x29, x30, [sp, #-64]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    mov     x19, x0
    mov     w20, w1
    mov     x21, x2
    mov     w22, w3
    mov     x23, x4

    adr     x8, payload_base
    mov     x9, #PAYLOAD_OFF
    sub     x8, x8, x9
    add     x9, x8, #0xf3000
    add     x9, x9, #MAGIC_OFF
    adr     x10, magic
    ldp     x11, x12, [x10]
    ldp     x13, x14, [x9]
    cmp     x11, x13
    b.ne    8f
    cmp     x12, x14
    b.ne    8f

    /* Find the base FDT whose totalsize equals the header dtb_size.
     * For our zero-ramdisk v2 image LK's pointer is 0x1000 past it. */
    mov     x24, x19
    mov     w15, #0x1000            /* scan 0x4000 bytes back, 4-byte steps */
1:
    ldr     w8, [x24]
    mov     w9, #0x0dd0
    movk    w9, #0xedfe, lsl #16    /* FDT magic 0xd00dfeed */
    cmp     w8, w9
    b.ne    2f
    ldr     w8, [x24, #4]
    rev     w8, w8
    cmp     w8, w20
    b.eq    3f
2:
    sub     x24, x24, #4
    subs    w15, w15, #1
    b.ne    1b
    b       5f

3:  adr     x0, msg_ovl_base
    mov     x1, x24
    mov     w2, w20
    bl      lk_printf
    mov     x0, x24
    mov     w1, w20
    mov     x2, x21
    mov     w3, w22
    mov     x4, x23
    bl      overlay_apply
    cbz     w0, 7f
    adr     x0, msg_ovl_fail
    bl      lk_printf

    /* Skip the overlay: keep the FDT at LK's original base pointer, so
     * the downstream free() of a changed pointer cannot happen. */
    cmp     x24, x19
    b.eq    4f
    mov     x0, x19
    mov     x1, x24
    mov     w2, w20
    bl      memmove_up
4:
    str     x19, [x23]
    mov     w0, #0
    b       7f

5:  adr     x0, msg_no_fdt
    mov     x1, x19
    mov     w2, w20
    bl      lk_printf
    str     x19, [x23]
    mov     w0, #0
    b       7f

8:  mov     x0, x19
    mov     w1, w20
    mov     x2, x21
    mov     w3, w22
    mov     x4, x23
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x29, x30, [sp], #64
    b       overlay_apply

7:
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x29, x30, [sp], #64
    ret

memmove_up:
    /* x0=dst, x1=src, w2=size; dst > src, ranges overlap. */
    and     x3, x2, #7
    sub     x2, x2, x3
    add     x4, x1, x2
    add     x5, x0, x2
1:
    cmp     x4, x1
    b.ls    2f
    sub     x4, x4, #8
    sub     x5, x5, #8
    ldr     x6, [x4]
    str     x6, [x5]
    b       1b
2:
    cbz     x3, 3f
    ldr     w6, [x1, x2]
    str     w6, [x0, x2]
3:
    ret

    .text
    .global bootconfig_hook
bootconfig_hook:
    /* Called from 0xcb7c instead of the bootconfig appender (0xadd4).
     * The destination is the vendor ramdisk at 0x66f00000 + ramdisk_size,
     * which only exists after the stock storage loader.  RAWBOOT-UEFI
     * skips the append (return 0 bytes added); normal boot is unchanged. */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    adr     x8, payload_base
    mov     x9, #PAYLOAD_OFF
    sub     x8, x8, x9
    add     x9, x8, #0xf3000
    add     x9, x9, #MAGIC_OFF
    adr     x10, magic
    ldp     x11, x12, [x10]
    ldp     x13, x14, [x9]
    cmp     x11, x13
    b.ne    1f
    cmp     x12, x14
    b.ne    1f
    adr     x0, msg_no_bootconfig
    bl      lk_printf
    mov     w0, #0
    ldp     x29, x30, [sp], #16
    ret
1:
    ldp     x29, x30, [sp], #16
    b       bootconfig_append

    .global boot_handler
boot_handler:
    /* handler(arg=x0, download_base=x1, download_size=x2) */
    stp     x29, x30, [sp, #-80]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    str     x25, [sp, #64]

    mov     x19, x1                     /* download buffer (PA/identity VA) */
    mov     x20, x2                     /* download size */

    /* LK base = payload_base - 0x1880 */
    adr     x21, payload_base
    mov     x9, #PAYLOAD_OFF
    sub     x21, x21, x9

    cmp     x20, #0x28
    b.lo    bad_size

    ldr     x8, [x19]
    ldr     x9, =0x21544F4F42574152     /* "RAWBOOT!" little-endian */
    cmp     x8, x9
    b.eq    raw_payload

    /* Our own v2 boot image is marked by name "RAWBOOT-UEFI" at +0x30;
     * use LK's normal kernel boot path instead of the direct SMC. */
    ldr     x9, =0x2D544F4F42574152     /* "RAWBOOT-" little-endian */
    ldr     x10, [x19, #0x30]
    cmp     x10, x9
    b.eq    bootimg

    /* platform-tools `fastboot boot` wraps a non-boot-image file into a
     * boot image: "ANDROID!" + header page, kernel at page_size.  Look for
     * our RAWBOOT payload at that offset. */
    ldr     x9, =0x2144494F52444E41     /* "ANDROID!" little-endian */
    cmp     x8, x9
    b.ne    bad_magic

    ldr     w10, [x19, #0x24]           /* page_size (0 for v3/v4) */
    cmp     w10, #0x800
    b.hs    1f
    mov     w10, #0x1000
1:
    cmp     w10, #0x10000
    b.ls    2f
    mov     w10, #0x1000
2:
    cmp     x20, x10
    b.lo    bad_size
    add     x19, x19, x10
    sub     x20, x20, x10
    cmp     x20, #0x28
    b.lo    bad_size
    ldr     x8, [x19]
    ldr     x9, =0x21544F4F42574152     /* "RAWBOOT!" little-endian */
    cmp     x8, x9
    b.ne    bad_magic
    adr     x0, msg_wrapped
    mov     x1, x10
    bl      lk_printf

raw_payload:

    ldr     x24, [x19, #0x20]           /* payload_size */
    add     x9, x24, #0x28
    cmp     x9, x20
    b.hi    bad_size

    ldr     x22, [x19, #0x18]           /* dtb_addr (may be 0) */
    ldr     x10, [x19, #0x08]           /* load_addr; 0 = execute in place */
    cbz     x10, 3f

    /* Copy the payload to the standard kernel PA via LK's linear high VA
     * (VA = 0xffff000000000000 + PA).  LK maps the low DRAM window this way
     * for the DTB/kernel; ATF/GZ expects the kernel at 0x40080000. */
    mov     x23, x10                    /* SMC entry PA */
    mov     x0, x10
    bl      vmm_get_va                  /* LK's actual mapping for this PA */
    cbnz    x0, 5f
    mov     x25, x23                    /* fallback: low identity VA */
    b       6f
5:  mov     x25, x0
6:
    adr     x0, msg_copy
    mov     x1, x23
    mov     x2, x25
    bl      lk_printf
    mov     x0, x25
    add     x1, x19, #0x28
    mov     x2, x24
    bl      lk_memcpy
    mov     x0, x25
    mov     x1, x24
    bl      clean_cache
    b       4f

3:  /* in-place path */
    add     x23, x19, #0x28             /* entry = payload start */
    adr     x0, msg_start
    mov     x1, x24
    mov     x2, x23
    mov     x3, x22
    bl      lk_printf
    mov     x0, x19
    add     x1, x24, #0x28
    bl      clean_cache

4:
    ic      iallu
    dsb     sy
    isb

    /* Reuse LK's final boot path: x0=SMC stub VA, x1=SIP, x2=entry,
     * x3=DTB, x4=arg.  0x1CA10 quiesces, disables caches and SMCs to ATF;
     * it does not return on success. */
    add     x0, x21, #0xd000
    add     x0, x0, #0xc8
    mov     x1, #0x115
    movk    x1, #0xc200, lsl #16
    mov     x2, x23
    mov     x3, x22
    mov     x4, #0
    bl      boot_jump

    /* SMC returned: report and stay in fastboot. */
    mov     w1, w0
    adr     x0, msg_returned
    bl      lk_printf
    b       out

bootimg:
    /* LK normal boot path: parse the v2 image, skip the storage loader via
     * the magic, then let boot_linux_from_storage decompress/copy the
     * kernel to its kernel_addr and call SMC. */
    add     x9, x21, #0xf3000
    strb    wzr, [x9, #BOOT_MODE_OFF]
    mov     x0, x19
    bl      load_bootinfo
    cbnz    w0, boot_fail
    mov     x0, x19
    mov     x1, #0
    bl      bootinfo_set_image
    adr     x10, magic
    ldp     x11, x12, [x10]
    add     x9, x21, #0xf3000
    add     x9, x9, #MAGIC_OFF
    stp     x11, x12, [x9]
    adr     x0, msg_bootimg
    bl      lk_printf
    bl      boot_linux_from_storage
    add     x9, x21, #0xf3000
    add     x9, x9, #MAGIC_OFF
    stp     xzr, xzr, [x9]
    mov     w1, w0
    adr     x0, msg_fail
    bl      lk_printf
    mov     w0, #-4
    b       out
boot_fail:
    mov     w0, #-5
    b       out

bad_magic:
    adr     x0, msg_bad_magic
    bl      lk_printf
    mov     w0, #-2
    b       out
bad_size:
    adr     x0, msg_bad_size
    bl      lk_printf
    mov     w0, #-3
    b       out
out:
    ldr     x25, [sp, #64]
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x29, x30, [sp], #80
    ret

    .section .rodata, "a"
    .balign 4
boot_cmd:
    .asciz "boot"

msg_start:
    .asciz "kaeru-rawboot: payload=0x%x entry=0x%x dtb=0x%x\n"
msg_wrapped:
    .asciz "kaeru-rawboot: host boot.img page=0x%x\n"
msg_bootimg:
    .asciz "kaeru-rawboot: bootimg -> boot_linux_from_storage\n"
msg_skip:
    .asciz "kaeru-rawboot: skip storage loader (bootimg magic)\n"
msg_copy:
    .asciz "kaeru-rawboot: copy payload pa=0x%x va=0x%x\n"
msg_returned:
    .asciz "kaeru-rawboot: boot_jump returned %d\n"
msg_bad_magic:
    .asciz "kaeru-rawboot: bad magic (want RAWBOOT!)\n"
msg_bad_size:
    .asciz "kaeru-rawboot: bad size\n"
msg_fail:
    .asciz "kaeru-rawboot: boot_linux_from_storage returned %d\n"
msg_ovl_base:
    .asciz "kaeru-rawboot: overlay base=0x%x size=0x%x\n"
msg_ovl_fail:
    .asciz "kaeru-rawboot: overlay failed, skipped\n"
msg_no_fdt:
    .asciz "kaeru-rawboot: no fdt for overlay (base=0x%x size=0x%x)\n"
msg_no_bootconfig:
    .asciz "kaeru-rawboot: bootconfig skipped\n"

    .balign 8
    .global magic
magic:
    /* "KAERU-FB-BOOT!!!" */
    .quad 0x42462D555245414B
    .quad 0x212121544F4F422D

    .section .note.GNU-stack, "", %progbits
