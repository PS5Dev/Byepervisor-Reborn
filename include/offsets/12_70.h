#ifndef OFFSETS_12_70_H
#define OFFSETS_12_70_H

static const uint64_t g_sym_map_1270[] = {
  0x3B6D254,  // KERNEL_SYM_DMPML4I
  0x3B6D258,  // KERNEL_SYM_DMPDPI
  0x3B6BE0C,  // KERNEL_SYM_PML4PML4I
  0x3573B0,   // KERNEL_SYM_SYS_GETUID
  0x544190,   // KERNEL_SYM_PRINTF
  0x43C150,   // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK
  0xC9DFB0,   // KERNEL_SYM_HV_MP_STARTUP_CALL
  0x318678,   // KERNEL_SYM_MP_STARTUP_INIT_VECTOR
  0x3B6CFB8,  // KERNEL_SYM_PMAP_STORE
  0x2DB5000,  // KERNEL_SYM_DATA_CAVE
  0x3BD8300,  // KERNEL_SYM_IDT_ARRAY
  0x3BDAFE0,  // KERNEL_SYM_COMMON_TSS
  0x83028,    // HV_SYM_HEAP_BASE
  0x82A60,    // HV_SYM_PCPUS
};

static const uint64_t g_gadget_map_1270[] = {
  0x2A815E,  // KERNEL_GADGET_PIVOT_ADD_RSP28_RET  add rsp,0x28 ; ret
  0x2B34AD,  // KERNEL_GADGET_IRETQ                iretq
  0x26E8D0,  // KERNEL_GADGET_POP_RAX              pop rax ; ret
  0x3410D2,  // KERNEL_GADGET_POP_RCX              pop rcx ; ret
  0x251C78,  // KERNEL_GADGET_POP_RDI              pop rdi ; ret
  0x2127B0,  // KERNEL_GADGET_POP_RSI              pop rsi ; ret
  0x34F4EB,  // KERNEL_GADGET_POP_RDX              pop rdx ; ret
  0xC18CED,  // KERNEL_GADGET_POP_R8               pop r8 ; ret
  0x2B6310,  // KERNEL_GADGET_POP_RSP              pop rsp ; ret
  0x51E699,  // KERNEL_GADGET_STORE_RCX_R8         mov [rcx], r8 ; ret
  0x3D66DF,  // KERNEL_GADGET_STORE_RDI8_RCX       mov [rdi+8], rcx ; ret
  0x899E20,  // KERNEL_GADGET_OR_RCX_EAX           or [rcx], eax ; ret
  0xA95A96,  // KERNEL_GADGET_SET_DR7              mov dr7,rax ; mov eax,r8d ; ret
  0x8BBA75,  // KERNEL_GADGET_ST_RCX_RDX           mov [rcx], rdx ; ret
  0x369DEF,  // KERNEL_GADGET_ST_RCX_RAX           mov [rcx], rax ; xor eax,eax ; ret
  0x971E64,  // KERNEL_GADGET_MOV_RAX_RSI          mov rax, rsi ; ret
  0x2B9D91,  // KERNEL_GADGET_MOV_RAX_RDI          mov rax, rdi ; ret
  0x30B6C7,  // KERNEL_GADGET_REP_MOVSB            rep movsb ; nop ; rep ret
  0x36A530,  // KERNEL_GADGET_CLD                  cld ; ret
  0x26E8D1,  // KERNEL_GADGET_RET_TRAMP            ret
  0x2AC9F8,  // KERNEL_GADGET_DBREG_RESUME         resumectx tail
};

#endif // OFFSETS_12_70_H
