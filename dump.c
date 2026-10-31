#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>

#include <ps5/kernel.h>

#include "kdlsym.h"
#include "paging.h"
#include "util.h"
#include "dump.h"

#ifndef DUMP_CHUNK
#define DUMP_CHUNK 0x4000u
#endif

/* HV loader base PA, set by main.c (depends on Pro vs regular model) */
extern uint64_t g_hv_base_pa;

static void find_kernel_size(uint64_t *ksize)
{
    uint8_t data[0x50];
    uint64_t vaddr = ((uint64_t)KERNEL_ADDRESS_ALLPROC + 0x1000 - 1) & ~(uint64_t)0xFFF;
    uint64_t limit = vaddr + 0x10000000;  /* 256 MB search ceiling */

    *ksize = 0;

    while (vaddr < limit) {
        kernel_copyout(vaddr, data, sizeof(data));

        /* Module info is at the end. */
        if (strcmp((char *)data + 0x08, "kernel") == 0 &&
            strcmp((char *)data + 0x18, "elf kernel") == 0) {
            *ksize = *(uint64_t *)(data + 0x40);
            return;
        }

        vaddr += 0x1000;
    }
}

int dump_kernel_text(const char *path)
{
    uint64_t ktext_base = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    uint64_t ksize = 0;
    uint64_t off;
    uint8_t *kbuf;
    int fd;

    printf("[+] finding kernel size...\n");
    find_kernel_size(&ksize);

    if (ksize == 0 || ksize > 0x40000000) {
        printf("[!] invalid kernel size 0x%lx\n", ksize);
        return -1;
    }

    printf("[+] kernel size: 0x%lx (%lu MB), dumping from 0x%lx in 0x%x chunks -> %s\n",
           ksize, (unsigned long)(ksize >> 20), ktext_base, DUMP_CHUNK, path);

    kbuf = malloc(ksize);
    if (!kbuf) {
        printf("[!] malloc(0x%lx) failed\n", ksize);
        return -1;
    }

    for (off = 0; off < ksize; off += DUMP_CHUNK) {
        uint64_t n = ksize - off;

        if (n > DUMP_CHUNK)
            n = DUMP_CHUNK;

        kernel_copyout(ktext_base + off, kbuf + off, (size_t)n);

        if ((off & 0xFFFFF) == 0) {
            printf("\r    0x%lx / 0x%lx", off, ksize);
            fflush(stdout);
        }
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        printf("\n[!] open(%s) failed\n", path);
        free(kbuf);
        return -1;
    }

    if (write(fd, kbuf, (size_t)ksize) != (ssize_t)ksize) {
        printf("\n[!] write failed\n");
        close(fd);
        free(kbuf);
        return -1;
    }

    close(fd);
    free(kbuf);

    printf("\n[+] dumped 0x%lx bytes (%lu MB) -> %s\n",
           ksize, (unsigned long)(ksize >> 20), path);
    return 0;
}


int dump_hv_image(const char *path)
{
    Elf64_Ehdr ehdr;
    uint64_t elf_pa, ka, hv_size;
    uint64_t off;
    uint8_t *kbuf;
    int fd;

    if (!g_hv_base_pa) {
        printf("[!] HV pa is 0, skipping HV dump\n");
        return -1;
    }

    /* HV ELF image sits HV_ELF_OFF past the HV loader base */
    elf_pa = g_hv_base_pa + HV_ELF_OFF;
    ka = kdldmap(elf_pa);

    kernel_copyout(ka, &ehdr, sizeof(ehdr));
    if (ehdr.e_ident[0] != ELFMAG0 || ehdr.e_ident[1] != ELFMAG1 ||
        ehdr.e_ident[2] != ELFMAG2 || ehdr.e_ident[3] != ELFMAG3) {
        printf("[!] no ELF header at HV pa 0x%lx (byte 0x%02x), skipping HV dump\n",
               elf_pa, ehdr.e_ident[0]);
        return -1;
    }

    hv_size = ehdr.e_shoff + (uint64_t)ehdr.e_shnum * (uint64_t)ehdr.e_shentsize;
    if (hv_size == 0 || hv_size > 0x4000000) {
        printf("[!] bad HV ELF size 0x%lx (shoff 0x%lx shnum %u shentsize %u)\n",
               hv_size, (uint64_t)ehdr.e_shoff, ehdr.e_shnum, ehdr.e_shentsize);
        return -1;
    }

    printf("[+] dumping HV from pa 0x%lx (ka 0x%lx, size 0x%lx, ELF shoff 0x%lx) in 0x%x chunks -> %s\n",
           elf_pa, ka, hv_size, (uint64_t)ehdr.e_shoff, DUMP_CHUNK, path);

    kbuf = malloc(hv_size);
    if (!kbuf) {
        printf("[!] malloc(0x%lx) failed\n", hv_size);
        return -1;
    }

    for (off = 0; off < hv_size; off += DUMP_CHUNK) {
        uint64_t n = hv_size - off;

        if (n > DUMP_CHUNK)
            n = DUMP_CHUNK;

        kernel_copyout(ka + off, kbuf + off, (size_t)n);

        if ((off & 0xFFFFF) == 0 || off + n == hv_size) {
            printf("\r    0x%lx / 0x%lx", off + n, hv_size);
            fflush(stdout);
        }
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        printf("\n[!] open(%s) failed\n", path);
        free(kbuf);
        return -1;
    }

    if (write(fd, kbuf, (size_t)hv_size) != (ssize_t)hv_size) {
        printf("\n[!] write failed\n");
        close(fd);
        free(kbuf);
        return -1;
    }

    close(fd);
    free(kbuf);

    printf("\n[+] dumped 0x%lx bytes (%lu KB) -> %s\n",
           hv_size, (unsigned long)(hv_size >> 10), path);
    return 0;
}