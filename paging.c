#include <stdio.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "kdlsym.h"
#include "util.h"
#include "paging.h"

uint64_t get_proc_pmap()
{
  pid_t pid;
  uint64_t proc;
  uint64_t p_vmspace;
  uint64_t vm_pmap;

  // Get process pid
  pid = getpid();

  // Get proc
  proc = kernel_get_proc(pid);
  if (proc == 0) {
    return 0;
  }

  // Get proc->p_vmspace
  p_vmspace = kread64(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
  if (p_vmspace == 0) {
    return 0;
  }

  // Get vmspace->vm_pmap
  vm_pmap = kread64(p_vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP);
  if (vm_pmap == 0) {
    return 0;
  }

  return vm_pmap;
}

uint64_t pmap_kextract(uint64_t va)
{
  uint64_t DMPML4I;
  uint64_t DMPDPI;
  uint64_t PML4PML4I;
  uint64_t dmap;
  uint64_t dmap_end;
  uint64_t pde_addr;
  uint64_t pte_addr;
  uint64_t pde;
  uint64_t pte;

  DMPML4I   = (uint64_t) kread32(kdlsym(KERNEL_SYM_DMPML4I));
  DMPDPI    = (uint64_t) kread32(kdlsym(KERNEL_SYM_DMPDPI));
  PML4PML4I = (uint64_t) kread32(kdlsym(KERNEL_SYM_PML4PML4I));

  dmap     = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000;
  dmap_end = ((DMPML4I +1 ) << 39) | 0xFFFF800000000000;

  if (dmap <= va && dmap_end > va) {
    return va - dmap;
  }

  pde_addr = ((PML4PML4I << 39) | (PML4PML4I << 30) | 0xFFFF800000000000) + 8 * ((va >> 21) & 0x7FFFFFF);
  pde = kread64(pde_addr);
  if (pde & 0x80) {
    return (pde & 0xFFFFFFFE00000) | (va & 0x1FFFFF);
  }

  pte_addr = ((va >> 9) & 0xFE0) + dmap + (pde & 0xFFFFFFFFFF000);
  pte = kread64(pte_addr);

  return (pte & 0xFFFFFFFFFF000) | (va & 0x3FFF);
}

uint64_t find_pml4e(uint64_t pmap, uint64_t va, uint64_t *out_pml4e)
{
  uint64_t pml4e_addr;
  uint64_t pm_pml4;

  // Get pmap->pm_pml4
  pm_pml4 = kread64(pmap + KERNEL_OFFSET_PMAP_PM_PML4);
  if (pm_pml4 == 0) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  // Calculate pml4 entry via index encoded in virtual addr
  pml4e_addr = pm_pml4 + (((va >> 39) & 0x1FF) * 8);

  // Copy pml4e out and return address of it
  *out_pml4e = kread64(pml4e_addr);
  // printf("find_pml4e(0x%lx): pml4e addr = 0x%lx, pml4e = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx)\n",
  //   va, pml4e_addr, *out_pml4e, PDE_FIELD(*out_pml4e, RW), PDE_FIELD(*out_pml4e, EXECUTE_DISABLE), PDE_FIELD(*out_pml4e, USER), PDE_FIELD(*out_pml4e, XOTEXT));
  return pml4e_addr;
}

uint64_t find_pdpe(uint64_t pmap, uint64_t va, uint64_t *out_pdpe)
{
  uint64_t pdpe_addr;
  uint64_t pdp_table_pml4_entry;
  uint64_t pdp_table_dmap_addr;

  // Get pdp table address from pml4 entry
  if (find_pml4e(pmap, va, &pdp_table_pml4_entry) == 0xFFFFFFFFFFFFFFFFull) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  // Calculate pdp entry via index encoded in virtual addr
  pdp_table_dmap_addr     = kdldmap(PDE_ADDR(pdp_table_pml4_entry));
  pdpe_addr               = pdp_table_dmap_addr + (((va >> 30) & 0x1FF) * 8);

  // Copy pdpe out and return address of it
  *out_pdpe = kread64(pdpe_addr);
  // printf("find_pdpe(0x%lx): pdpe addr = 0x%lx, pdpe = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx)\n",
  //    va, pdpe_addr, *out_pdpe, PDE_FIELD(*out_pdpe, RW), PDE_FIELD(*out_pdpe, EXECUTE_DISABLE), PDE_FIELD(*out_pdpe, USER), PDE_FIELD(*out_pdpe, XOTEXT));
  return pdpe_addr;
}

uint64_t find_pde(uint64_t pmap, uint64_t va, uint64_t *out_pde)
{
  uint64_t pde_addr;
  uint64_t pd_table_pdp_entry;
  uint64_t pd_table_dmap_addr;

  // Get pd table address from pdp entry
  if (find_pdpe(pmap, va, &pd_table_pdp_entry) == 0xFFFFFFFFFFFFFFFFull) {
    return 0xFFFFFFFFFFFFFFFFull;
  }
  if (!(pd_table_pdp_entry & (1ULL << PDE_PRESENT)) ||
      PDE_FIELD(pd_table_pdp_entry, PS)) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  // Calculate pd entry via index encoded in virtual addr
  pd_table_dmap_addr      = kdldmap(PDE_ADDR(pd_table_pdp_entry));
  pde_addr                = pd_table_dmap_addr + (((va >> 21) & 0x1FF) * 8);

  // Copy pde out and return address of it
  *out_pde = kread64(pde_addr);
  // printf("find_pde(0x%lx): pde addr = 0x%lx, pde = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx, s: 0x%lx)\n",
  //   va, pde_addr, *out_pde, PDE_FIELD(*out_pde, RW), PDE_FIELD(*out_pde, EXECUTE_DISABLE), PDE_FIELD(*out_pde, USER), PDE_FIELD(*out_pde, XOTEXT), PDE_FIELD(*out_pde, PS));
  return pde_addr;
}

uint64_t find_pte(uint64_t pmap, uint64_t va, uint64_t *out_pte)
{
  uint64_t pte_addr;
  uint64_t page_table_pde_entry;
  uint64_t page_table_dmap_addr;

  // Get page table address from pde entry
  if (find_pde(pmap, va, &page_table_pde_entry) == 0xFFFFFFFFFFFFFFFFull) {
    return 0xFFFFFFFFFFFFFFFFull;
  }
  if (!(page_table_pde_entry & (1ULL << PDE_PRESENT)) ||
      PDE_FIELD(page_table_pde_entry, PS)) {
    return 0xFFFFFFFFFFFFFFFFull;
  }

  // Calculate pt entry via index encoded in virtual addr
  page_table_dmap_addr    = kdldmap(PDE_ADDR(page_table_pde_entry));
  pte_addr                = page_table_dmap_addr + (((va >> 12) & 0x1FF) * 8);

  // Copy pte out and return address of it
  *out_pte = kread64(pte_addr);
  // printf("find_pte(0x%lx): pte addr = 0x%lx, pte = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx)\n",
  //   va, pte_addr, *out_pte, PDE_FIELD(*out_pte, RW), PDE_FIELD(*out_pte, EXECUTE_DISABLE), PDE_FIELD(*out_pte, USER), PDE_FIELD(*out_pte, XOTEXT));
  return pte_addr;
}
