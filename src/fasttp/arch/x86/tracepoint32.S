.macro save_state
    push %esp
    pushf
    push %ebp
    push %ebx
    push %ecx
    push %edx
    push %esi
    push %edi
    push %eax
.endm

.macro restore_state
    pop %eax
    pop %edi
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx
    pop %ebp
    popf
    pop %esp
.endm

.macro enter_handler name, handler, disp=0
.global \name
.type \name, @function
\name\():
    save_state
    mov 0x24(%esp), %ebp
    mov \disp(%ebp), %ebp
    lock incl (%ebp)
    push %esp
    call \handler\()@plt
    add $4, %esp
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
    mov 0x24 (%esp), %ebp
    mov (%ebp), %ebp
    push %esp
    call tracepoint_return_exit_handler@plt
    add $4, %esp
    lock decl (%ebp)
    restore_state
    ret
.__tracepoint_return_exit_handler_end:
.size __tracepoint_return_exit_handler, . - __tracepoint_return_exit_handler

test_enter:
    call .L0
.L0:
    pop %ebp
    call *0x8(%ebp)
test_exit:
    push %ebp
    pushf
    call .L1
.L1:
    pop %ebp
    mov -0x19(%ebp), %ebp
    lock decl (%ebp)
    popf
    pop %ebp

/////////////////////////////////////////////////////////////////////
.section .rodata
/////////////////////////////////////////////////////////////////////
symbol_size __tracepoint_handler
symbol_size __tracepoint_return_enter_handler
symbol_size __tracepoint_return_exit_handler