ENTRY(dmesh_module_entry)

SECTIONS {
  . = DEFINED(MODULE_VMA) ? MODULE_VMA : 0;
  .text : ALIGN(4) { *(.literal .literal.*) *(.text .text.*) }
  .rodata : ALIGN(4) { *(.rodata .rodata.*) }
  /DISCARD/ : { *(.comment*) *(.eh_frame*) *(.note*) }
}
