#ifndef OFFSETS_11_40_H
#define OFFSETS_11_40_H

static const uint64_t g_sym_map_1140[] = {
  0x3B351B4,  // KERNEL_SYM_DMPML4I         (pmap_store + 0x29C, pattern verified across all FW)
  0x3B351B8,  // KERNEL_SYM_DMPDPI          (pmap_store + 0x2A0, always DMPML4I + 4)
  0x3B33D6C,  // KERNEL_SYM_PML4PML4I       (pmap_store - 0x11AC, pattern verified across all FW)
  0x0,        // KERNEL_SYM_SYS_GETUID      (only used in KHOOK_TEST debug path)
  0x5362F0,   // KERNEL_SYM_PRINTF          (from ps5-linux-loader 11.40)
  0x0,        // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK (not used by Byepervisor main flow)
  0xC88A10,   // KERNEL_SYM_HV_MP_STARTUP_CALL     (from ps5-linux-loader 11.40)
  0x311E98,   // KERNEL_SYM_MP_STARTUP_INIT_VECTOR  (from ps5-linux-loader 11.40)
  0x3B34F18,  // KERNEL_SYM_PMAP_STORE      (kstuff-lite kernel_pmap_store 0x2E04F18 + T 0xD30000)
  0x2D02000,  // KERNEL_SYM_DATA_CAVE       (from ps5-linux-loader 11.40)
  0x3BA0300,  // KERNEL_SYM_IDT_ARRAY       (from ps5-linux-loader 11.40, verified kstuff idt + T)
  0x3BA2FE0,  // KERNEL_SYM_COMMON_TSS      (from ps5-linux-loader 11.40, verified kstuff tss + T)
  0x83028,    // HV_SYM_HEAP_BASE           (constant across all FW)
  0x82A60,    // HV_SYM_PCPUS               (constant across all FW)
};

static const uint64_t g_gadget_map_1140[] = {
  0x2A1C9E,   // KERNEL_GADGET_PIVOT_ADD_RSP28_RET  (from ps5-linux-loader 11.40)
  0x26BFA7,   // KERNEL_GADGET_IRETQ                (from ps5-linux-loader 11.40)
  0x268410,   // KERNEL_GADGET_POP_RAX               (from ps5-linux-loader 11.40)
  0x339EAF,   // KERNEL_GADGET_POP_RCX               (from ps5-linux-loader 11.40)
  0x24B7B8,   // KERNEL_GADGET_POP_RDI               (from ps5-linux-loader 11.40)
  0x20C2F0,   // KERNEL_GADGET_POP_RSI               (from ps5-linux-loader 11.40)
  0x3484BB,   // KERNEL_GADGET_POP_RDX               (from ps5-linux-loader 11.40)
  0,          // KERNEL_GADGET_POP_R8         (unused by the isolated 11.40 resume path)
  0x2AFE50,   // KERNEL_GADGET_POP_RSP               (from ps5-linux-loader 11.40)
  0,          // KERNEL_GADGET_STORE_RCX_R8   (unused by the isolated 11.40 resume path)
  0x3CD28F,   // KERNEL_GADGET_STORE_RDI8_RCX        (from ps5-linux-loader 11.40)
  0,          // KERNEL_GADGET_OR_RCX_EAX     (unused by the isolated 11.40 resume path)
  0xA7C306,   // KERNEL_GADGET_SET_DR7               (from ps5-linux-loader 11.40)
  0,          // KERNEL_GADGET_ST_RCX_RDX     (unused by the isolated 11.40 resume path)
  0x362E9F,   // KERNEL_GADGET_ST_RCX_RAX            (from ps5-linux-loader 11.40)
  0,          // KERNEL_GADGET_MOV_RAX_RSI    (unused by the isolated 11.40 resume path)
  0x2B38D1,   // KERNEL_GADGET_MOV_RAX_RDI           (from ps5-linux-loader 11.40)
  0x305127,   // KERNEL_GADGET_REP_MOVSB             (from ps5-linux-loader 11.40)
  0x3ED2D7,   // KERNEL_GADGET_CLD                   (from ps5-linux-loader 11.40)
  0x268411,   // KERNEL_GADGET_RET_TRAMP              (from ps5-linux-loader 11.40)
  0x2A6538,   // KERNEL_GADGET_DBREG_RESUME           (from ps5-linux-loader 11.40)
};

#endif // OFFSETS_11_40_H
