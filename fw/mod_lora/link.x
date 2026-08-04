ENTRY(dmesh_module_entry)

SECTIONS {
  /* Optional fixed instruction-window link address; see mod_hello/link.x. */
  . = DEFINED(MODULE_VMA) ? MODULE_VMA : 0;
  .text : ALIGN(4) { *(.literal .literal.*) *(.text .text.*) }
  .rodata : ALIGN(4) { *(.rodata .rodata.*) }
  /DISCARD/ : { *(.comment*) *(.eh_frame*) *(.note*) }
}
