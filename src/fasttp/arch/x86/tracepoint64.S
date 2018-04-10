
.macro save_state
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
.endm

.macro restore_state
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
.endm

.macro enter_handler name, handler, disp=0
.global \name
.type \name, @function
\name\():
    save_state
    mov 0x88(%rsp), %rbp
    mov \disp(%rbp), %rbp
    lock incq (%rbp)
    mov %rsp, %rdi
    call \handler\()@plt
    restore_state
    ret
.\name\()_end:
.size \name, . - \name
.endm

.macro symbol_size symbol
.global \symbol\()_size
.type \symbol\()_size, @object
\symbol\()_size: .quad .\symbol\()_end - \symbol
.size \symbol\()_size, . - \symbol\()_size
.endm

/////////////////////////////////////////////////////////////////////
.section .text
/////////////////////////////////////////////////////////////////////

enter_handler __tracepoint_handler, tracepoint_handler
enter_handler __tracepoint_return_enter_handler, tracepoint_return_enter_handler, 6

.global __tracepoint_return_exit_handler
.type __tracepoint_return_exit_handler, @function
__tracepoint_return_exit_handler:
    save_state
    mov 0x88 (%rsp), %rbp
    mov (%rbp), %rbp
    mov %rsp, %rdi
    call tracepoint_return_exit_handler@plt
    lock decq (%rbp)
    restore_state
    ret
.__tracepoint_return_exit_handler_end:
.size __tracepoint_return_exit_handler, . - __tracepoint_return_exit_handler

test:
    push %rcx
    movabs $1, %rcx
    cmpb $0, (%rcx)
    pop %rcx
test2:
    cmpb $0, (%rip)

/////////////////////////////////////////////////////////////////////
.section .rodata
/////////////////////////////////////////////////////////////////////
symbol_size __tracepoint_handler
symbol_size __tracepoint_return_enter_handler
symbol_size __tracepoint_return_exit_handler