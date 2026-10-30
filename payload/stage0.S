/*
 * Stage 0: paint the iQOO Z8 panel with the current EL color, then spin.
 *
 * Entered by ATF via SMC 0xC2000115 with MMU/caches off at the RAWBOOT
 * payload start.  Uses the LK mblock framebuffer at 0xFE20F000,
 * 1088 x 2388, 32bpp.  red=EL1, green=EL2, blue=EL3.
 */
    .arch armv8-a
    .section .text, "ax"
    .global _start
_start:
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    mov     w1, #0x00FF0000         /* EL1: red */
    cmp     x0, #1
    b.eq    color
    mov     w1, #0x0000FF00         /* EL2: green */
    cmp     x0, #2
    b.eq    color
    mov     w1, #0x000000FF         /* EL3: blue */

color:
    movz    x2, #0xF000
    movk    x2, #0xFE20, lsl #16    /* FB base 0xFE20F000 */
    mov     w3, #2388               /* rows */
row:
    mov     w4, #1088               /* pitch pixels */
pix:
    str     w1, [x2], #4
    subs    w4, w4, #1
    b.ne    pix
    subs    w3, w3, #1
    b.ne    row

loop:
    wfe
    b       loop
