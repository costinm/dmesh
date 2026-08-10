ENTRY(dmesh_module_entry)

SECTIONS {
  . = MODULE_VMA;
  .text ALIGN(4) : { *(.literal .literal.*) *(.text .text.*) }
  .rodata MODULE_DATA_VMA : AT(LOADADDR(.text) + SIZEOF(.text)) ALIGN(4) {
    *(.rodata .rodata.*)
  }
  /DISCARD/ : { *(.comment*) *(.eh_frame*) *(.note*) }
}
