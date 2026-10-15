ENTRY(shellcode)
SECTIONS
{
  . = 0;
  .text : SUBALIGN(1) {
    entry_1270.o(.text .text.*)
    *(.text .text.*)
  }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  /DISCARD/ : {
    *(.eh_frame .eh_frame_hdr)
    *(.note .note.*)
    *(.comment)
    *(.bss .bss.*)
  }
}
