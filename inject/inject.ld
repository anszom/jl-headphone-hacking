MEMORY {
  rom (rx)  : ORIGIN = 0x1e6a700, LENGTH = 0x20000
  ram (rwx) : ORIGIN = 0x15ac4, LENGTH = 0x1000 /* there is way more RAM there, but let's be conservative */
  overlay (rwx): ORIGIN = 0xd784, LENGTH = 0x833a /* size of the AEC overlay. AAC is smaller */
}

PROVIDE(jiffies = 0x1518);
PROVIDE(p33_soft_reset = 0xc520);

#include "app.ld"

SECTIONS
{
  .overlay : {
#ifdef USE_TREMOR_OVERLAY
    tremor/mdct.o(.rodata .rodata.*)
    tremor/floor_lookup.o(.rodata .rodata.*)
#endif
  } > overlay AT> rom

  __overlay_start = ADDR(.overlay);
  __overlay_end = __overlay_start + SIZEOF(.overlay);
  __overlay_ceiling = ADDR(.overlay) + LENGTH(overlay);
  __overlay_load = LOADADDR(.overlay);

  /* Fixed-size slot for the tremor decoder. Kept first and at a constant size
     so edits to any other object never shift tremor's code/rodata. */
  .text.tremor : {
    __tremor_slot_start = .;
    "tremor/*.o"(.text .text.*)
    "tremor/*.o"(.rodata .rodata.* .srodata .srodata.*)
    . = __tremor_slot_start + 0x12000;
  } > rom

  /* Fixed-size slot for everything else; at a constant address because the
     tremor slot above has a constant size. */
  .text.inject : {
    __inject_slot_start = .;
    *(.text .text.*)
    *(.rodata .rodata.* .srodata .srodata.*)
    . = __inject_slot_start + 0x1000;
  } > rom

  .data.inject : {
    *(.data .data.* .sdata .sdata.*)
    . = ALIGN(4);
  } > ram AT> rom

  __idata_start = ADDR(.data.inject);
  __idata_end = __idata_start + SIZEOF(.data.inject);
  __idata_load = LOADADDR(.data.inject);

  .noinit.inject (NOLOAD) : {
    *(.noinit)
  } > ram

  .bss.inject (NOLOAD) : {
    *(.bss .bss.* .sbss .sbss.* COMMON)
  } > ram

  __ibss_start = ADDR(.bss.inject);

  /* this is used by the patcher script as the end of our RAM,
   * we must not access anything past this point */
  __ibss_end = ADDR(.bss.inject) + SIZEOF(.bss.inject);

  .patchmeta 0 (INFO) : { KEEP(*(.patchmeta)) }

  /DISCARD/ : { *(.comment) *(.debug*) *(.riscv.attributes) }
}

