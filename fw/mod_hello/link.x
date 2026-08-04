ENTRY(dmesh_module_entry)

SECTIONS {
  /* Optional fixed instruction-window link address. The normal flat image
   * leaves this at zero; build.sh may pass --defsym=MODULE_VMA=<address> for
   * the MMU fixed-window experiment. */
  . = DEFINED(MODULE_VMA) ? MODULE_VMA : 0;
  .text : ALIGN(4) { *(.literal .literal.*) *(.text .text.*) }
  .rodata : ALIGN(4) { *(.rodata .rodata.*) }
  /DISCARD/ : { *(.comment*) *(.eh_frame*) *(.note*) }
}
