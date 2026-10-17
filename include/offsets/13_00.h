#ifndef OFFSETS_13_00_H
#define OFFSETS_13_00_H

uint64_t g_sym_map_1300[] = {
  0x3B25294,  // KERNEL_SYM_DMPML4I
  0x3B25298,  // KERNEL_SYM_DMPDPI
  0x3B23E4C,  // KERNEL_SYM_PML4PML4I
  0x2A8B20,   // KERNEL_SYM_SYS_GETUID
  0x4ABB00,   // KERNEL_SYM_PRINTF
  0x3909B0,   // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK
  0xC0A110,   // KERNEL_SYM_HV_MP_STARTUP_CALL
  0x269238,   // KERNEL_SYM_MP_STARTUP_INIT_VECTOR
  0x3B24FF8,  // KERNEL_SYM_PMAP_STORE
  0x2D29000,  // KERNEL_SYM_DATA_CAVE
  0x3B90300,  // KERNEL_SYM_IDT_ARRAY
  0x3B92FE0,  // KERNEL_SYM_COMMON_TSS
  0x83028,    // HV_SYM_HEAP_BASE
  0x82A60,    // HV_SYM_PCPUS
};

uint64_t g_gadget_map_1300[] = {
  0x2520FE,   // KERNEL_GADGET_PIVOT_ADD_RSP28_RET  add rsp,0x28 ; ret
  0x257AFD,   // KERNEL_GADGET_IRETQ                iretq
  0x291231,   // KERNEL_GADGET_POP_RAX              pop rax ; ret
  0x291842,   // KERNEL_GADGET_POP_RCX              pop rcx ; ret
  0x31A4A3,   // KERNEL_GADGET_POP_RDI              pop rdi ; ret
  0x2A46ED,   // KERNEL_GADGET_POP_RSI              pop rsi ; ret
  0x2A0D3B,   // KERNEL_GADGET_POP_RDX              pop rdx ; ret
  0xB820BD,   // KERNEL_GADGET_POP_R8               pop r8 ; ret
  0x291BD2,   // KERNEL_GADGET_POP_RSP              pop rsp ; ret
  0x472B09,   // KERNEL_GADGET_STORE_RCX_R8         mov [rcx], r8 ; ret
  0x325D8F,   // KERNEL_GADGET_STORE_RDI8_RCX       mov [rdi+8], rcx ; ret
  0x802E40,   // KERNEL_GADGET_OR_RCX_EAX           or [rcx], eax ; ret
  0x9FF536,   // KERNEL_GADGET_SET_DR7              mov dr7,rax ; mov eax,r8d ; ret
  0x8247D5,   // KERNEL_GADGET_ST_RCX_RDX           mov [rcx], rdx ; ret
  0x2BB04F,   // KERNEL_GADGET_ST_RCX_RAX           mov [rcx], rax ; xor eax,eax ; ret
  0x8DB9F4,   // KERNEL_GADGET_MOV_RAX_RSI          mov rax, rsi ; ret
  0xBE007A,   // KERNEL_GADGET_MOV_RAX_RDI          mov rax, rdi ; ret
  0x25CFE7,   // KERNEL_GADGET_REP_MOVSB            rep movsb ; nop ; rep ret
  0x2883B0,   // KERNEL_GADGET_CLD                  cld ; ret
  0x291232,   // KERNEL_GADGET_RET_TRAMP            ret
  0x252998,   // KERNEL_GADGET_DBREG_RESUME         resumectx tail
};

#endif // OFFSETS_13_00_H
