OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(payload_base)

SECTIONS
{
    /* Executable zero cave inside the LK text page (VBAR is 0x1000). */
    . = 0x1880;
    .text : {
        *(.text.start)
        *(.text*)
    }
    .rodata : {
        *(.rodata*)
    }

    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.comment)
        *(.eh_frame*)
    }

    /* Absolute LK image offsets (VA = 0xFFFF000080000000 + these). */
    fastboot_register           = 0x4be8;
    storage_image_loader        = 0x51a04;
    lk_printf                   = 0x6b570;
    clean_cache                 = 0x3790;   /* dc cvac range + dsb sy */
    lk_memcpy                   = 0x6beec;  /* memcpy(dst, src, size) */
    load_bootinfo               = 0x9d00;
    bootinfo_set_image          = 0xa6ec;
    boot_linux_from_storage     = 0xd0d4;
    vmm_get_va                  = 0x6849c;  /* (pa) -> va or 0 */
    boot_jump                   = 0x1ca10;  /* quiesce + cache off + SMC 0xC2000115 */
    overlay_apply               = 0x72700;  /* stock v2 dtbo overlay wrapper */
    bootconfig_append           = 0xadd4;   /* appends bootconfig to vendor ramdisk */
}
