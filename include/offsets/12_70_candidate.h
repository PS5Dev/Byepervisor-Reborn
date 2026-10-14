#ifndef OFFSETS_12_70_CANDIDATE_H
#define OFFSETS_12_70_CANDIDATE_H

/*
 * Candidate offsets extracted from EchoStretch's unpushed 12.70 ELF.
 * These are text-relative, as in the 13.xx tables. PMAP_STORE, IDT_ARRAY,
 * and COMMON_TSS also match the public kstuff-lite data-relative table after
 * applying the SDK's 0xD50000 text/data gap. POP_RDI and CLD were replaced
 * with exact byte matches in the live 12.70 kernel-text dump. Other
 * instruction and HV offsets have not all been validated on 12.70 hardware.
 * The 12.70 table is included only in the separate 12.70 build target.
 */
uint64_t g_sym_map_1270[] = {
  0x3B6D254,  // KERNEL_SYM_DMPML4I
  0x3B6D258,  // KERNEL_SYM_DMPDPI
  0x3B6BE0C,  // KERNEL_SYM_PML4PML4I
  0x3573B0,   // KERNEL_SYM_SYS_GETUID; does not match live sysent getuid pointer
  0x544190,   // KERNEL_SYM_PRINTF
  0x43C150,   // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK
  0xC9DFB0,   // KERNEL_SYM_HV_MP_STARTUP_CALL
  0x318678,   // KERNEL_SYM_MP_STARTUP_INIT_VECTOR
  0x3B6CFB8,  // KERNEL_SYM_PMAP_STORE
  0x2D29000,  // KERNEL_SYM_DATA_CAVE
  0x3BD8300,  // KERNEL_SYM_IDT_ARRAY
  0x3BDAFE0,  // KERNEL_SYM_COMMON_TSS
  0x83028,    // HV_SYM_HEAP_BASE
  0x82A60,    // HV_SYM_PCPUS
};

uint64_t g_gadget_map_1270[] = {
  0x2A815E,   // KERNEL_GADGET_PIVOT_ADD_RSP28_RET
  0x272467,   // KERNEL_GADGET_IRETQ
  0xC9FBF4,   // KERNEL_GADGET_POP_RAX
  0x3410D2,   // KERNEL_GADGET_POP_RCX
  0x2A6784,   // KERNEL_GADGET_POP_RDI; live dump: 5f c3, executable text
  0x2F5CB0,   // KERNEL_GADGET_POP_RSI
  0x34F4EB,   // KERNEL_GADGET_POP_RDX
  0x7DEDBF,   // KERNEL_GADGET_POP_R8; isolated trigger KP, suspect/unverified
  0x341462,   // KERNEL_GADGET_POP_RSP
  0x51E699,   // KERNEL_GADGET_STORE_RCX_R8
  0x3D66DF,   // KERNEL_GADGET_STORE_RDI8_RCX
  0x899E20,   // KERNEL_GADGET_OR_RCX_EAX
  0xA95A96,   // KERNEL_GADGET_SET_DR7
  0x8BBA75,   // KERNEL_GADGET_ST_RCX_RDX
  0x369DEF,   // KERNEL_GADGET_ST_RCX_RAX
  0x971E64,   // KERNEL_GADGET_MOV_RAX_RSI
  0xC7380A,   // KERNEL_GADGET_MOV_RAX_RDI
  0x30B6C7,   // KERNEL_GADGET_REP_MOVSB
  0x369460,   // KERNEL_GADGET_CLD; live dump: fc c3, executable text
  0xC9FBF5,   // KERNEL_GADGET_RET_TRAMP
  0x2AC9F8,   // KERNEL_GADGET_DBREG_RESUME
};

#endif // OFFSETS_12_70_CANDIDATE_H
