ENTRY(_start)
SECTIONS {
	/*Our User Virtual Base*/
  . = 0x400000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : {
    *(.bss*)
    *(COMMON)
    _end = .;
  }
}