/* Fixed-VMA module layout. Code executes through the instruction MMU alias;
 * read-only literals use the corresponding data-bus alias. The load address
 * remains contiguous so objcopy produces one flash image. */
ENTRY(dmesh_module_entry)

SECTIONS {
  . = MODULE_VMA;
  .text ALIGN(4) : {
    *(.literal .literal.*)
    KEEP(*(.entry .entry.*))
    *(.text .text.*)
  }
  .rodata MODULE_DATA_VMA : AT(LOADADDR(.text) + SIZEOF(.text)) ALIGN(4) {
    *(.rodata .rodata.*)
  }
  /DISCARD/ : { *(.comment*) *(.eh_frame*) *(.note*) }
}
