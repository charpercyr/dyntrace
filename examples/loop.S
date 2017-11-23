test:
    // Save urgent registers (rsp, rbp, rflags)
    push %rsp
    push %rbp
    pushf
    // Increment refcount
    movabs $0x0123456789abcdef, %rbp
    lock incq (%rbp)
    // Save other registers
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
    // Call handler
    movabs $0xdeadbeefdeadbeef, %rdi
    mov %rsp, %rsi
    movabs $0xdeadbabedeadbabe, %rax
    call *%rax
    // Restore other registers
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
    // Decrement refcount
    movabs $0x0123456789abcdef, %rbp
    lock decq (%rbp)
    // Restore urgent registers (rsp, rbp, rflags)
    popf
    pop %rbp
    pop %rsp
    // Jump back
    jmp 0
.size test, . - test

.global do_inc
.type do_inc, @function
do_inc:
    movabs $1, %rax
    add %rax, (%rdi)
    ret
.size do_inc, . - do_inc

