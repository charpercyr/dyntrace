
.section .text
.global __tracepoint_handler
.type __tracepoint_handler, @function
__tracepoint_handler:
    push %rsp
    pushf
    push %rbp
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11
    push %r10
    push %rbx
    push %r9
    push %r8
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rax
    mov 0x88(%rsp), %rbp
    mov (%rbp), %rbp
    lock incq (%rbp)
    mov %rsp, %rdi
    call tracepoint_handler@plt
    pop %rax
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %r8
    pop %r9
    pop %rbx
    pop %r10
    pop %r11
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    pop %rbp
    popf
    pop %rsp
    ret
.__tracepoint_handler_end:
.size __tracepoint_handler, . - __tracepoint_handler

.section .rodata
.global __tracepoint_handler_size
.type __tracepoint_handler_size, @object
__tracepoint_handler_size: .quad .__tracepoint_handler_end - __tracepoint_handler
.size __tracepoint_handler_size, . - __tracepoint_handler_size